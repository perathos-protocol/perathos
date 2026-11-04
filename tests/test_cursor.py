"""Cursor hooks -> flight recorder, guard, checkpoints and hooks.json install.

Payloads follow the schema in Cursor's hooks reference
(https://cursor.com/docs/agent/hooks): common fields plus the per-event ones.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.cli import cli
from perathos.integrations import cursor
from perathos.recorder import content_hash, session_log_path, verify_session

CONV = "668320d2-2fd8-4888-b33c-2a466fec86e7"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    return tmp_path / "home"


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    p.mkdir()
    return p


def _common(event, project, gen="gen-1"):
    return {
        "conversation_id": CONV,
        "generation_id": gen,
        "model": "claude-sonnet-4-5",
        "hook_event_name": event,
        "cursor_version": "1.7.2",
        "workspace_roots": [str(project)],
        "user_email": None,
        "transcript_path": None,
    }


def _shell_before(project, command, gen="gen-1"):
    return {**_common("beforeShellExecution", project, gen), "command": command,
            "cwd": str(project / "src"), "sandbox": False}


def _shell_after(project, command, output, gen="gen-1"):
    return {**_common("afterShellExecution", project, gen), "command": command,
            "output": output, "duration": 1234, "sandbox": False}


def _mcp_before(project, tool, params, server="railway"):
    return {**_common("beforeMCPExecution", project), "tool_name": tool,
            "tool_input": json.dumps(params), "mcp_server_name": server, "command": "npx railway-mcp"}


def _mcp_after(project, tool, params, result, server="railway"):
    # The after event's tool_input deliberately uses different whitespace.
    return {**_common("afterMCPExecution", project), "tool_name": tool,
            "tool_input": json.dumps(params, indent=2), "mcp_server_name": server,
            "result_json": json.dumps(result), "duration": 88}


def _edit(project):
    return {**_common("afterFileEdit", project), "file_path": str(project / "app.py"),
            "edits": [{"old_string": "x = 1", "new_string": "x = 2"}]}


def _stop(project):
    return {**_common("stop", project), "status": "completed", "loop_count": 0}


def _run(runner, payload, *flags):
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    r = runner.invoke(cli, ["hooks", "record-cursor", *flags], input=raw)
    assert r.exit_code == 0, r.output
    return json.loads(r.stdout)


def _log(project):
    return session_log_path(project, CONV)


def _recs(project):
    return [json.loads(x) for x in _log(project).read_text(encoding="utf-8").splitlines() if x.strip()]


def _ok_cmd():
    return f'"{sys.executable}" -c "print(1)"'


# ── Recording ────────────────────────────────────────────────────────────────

def test_session_records_and_verifies(project, home):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    assert _run(runner, _shell_before(project, "pytest -q")) == {"continue": True, "permission": "allow"}
    assert _run(runner, _shell_after(project, "pytest -q", "5 passed")) == {}
    params = {"service": "web"}
    assert _run(runner, _mcp_before(project, "get_logs", params))["permission"] == "allow"
    _run(runner, _mcp_after(project, "get_logs", params, {"lines": ["ok"]}))
    _run(runner, _edit(project))
    _run(runner, _stop(project))

    recs = _recs(project)
    assert [r["kind"] for r in recs] == ["pre", "post", "pre", "post", "pre", "post", "checkpoint"]
    assert {r["agent"] for r in recs} == {"cursor"}
    assert [r["tool"] for r in recs[:6]] == ["Bash", "Bash", "mcp__railway__get_logs",
                                            "mcp__railway__get_logs", "Edit", "Edit"]
    # before/after pairs link through the derived tool_use_id
    assert recs[0]["tool_use_id"] == recs[1]["tool_use_id"]
    assert recs[2]["tool_use_id"] == recs[3]["tool_use_id"]
    assert recs[1]["result_hash"] == content_hash("5 passed")
    assert recs[2]["args_hash"] == recs[3]["args_hash"] == content_hash(params)
    cp = recs[-1]
    assert cp["event"] == "stop" and cp["model"] == "claude-sonnet-4-5" and cp["signature"]

    rep = verify_session(_log(project))
    assert rep.valid, rep.errors
    assert rep.tool_calls == 3 and rep.signed_checkpoints == 1
    assert not rep.warnings, rep.warnings  # every call has its result

    # only hashes are stored, never the content
    text = _log(project).read_text(encoding="utf-8")
    assert "pytest -q" not in text and "5 passed" not in text and "x = 2" not in text


def test_log_lives_in_workspace_root_not_shell_cwd(project, home):
    cursor.record_cursor_event(_shell_before(project, "ls"))
    assert _log(project).exists()
    assert not (project / "src" / ".perathos").exists()


def test_missing_output_hashes_payload(project, home):
    after = _shell_after(project, "make", "built")
    del after["output"]
    (rec,) = cursor.record_cursor_event(after)
    assert rec["result_from"] == "payload" and len(rec["result_hash"]) == 64


def test_workspace_root_normalisation(monkeypatch):
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    assert cursor.workspace_root({"workspace_roots": ["/c:/Users/me/proj"]}) == "c:/Users/me/proj"
    assert cursor.workspace_root({"workspace_roots": ["file:///home/me/proj"]}) == "/home/me/proj"
    assert cursor.workspace_root({"cwd": "/tmp/x"}) == "/tmp/x"
    assert cursor.workspace_root({}) == "."
    monkeypatch.setenv("CURSOR_PROJECT_DIR", "/env/proj")
    assert cursor.workspace_root({"cwd": "/tmp/x"}) == "/env/proj"


def test_unsigned_stop_without_key(project, home):
    _run(CliRunner(), _shell_before(project, "ls"))
    _run(CliRunner(), _stop(project))
    assert "signature" not in _recs(project)[-1]
    assert not verify_session(_log(project)).valid  # unsigned logs fail by default


# ── Guard ────────────────────────────────────────────────────────────────────

def test_guard_denies_destructive_shell_then_precondition_allows(project, home, monkeypatch):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    cmd = "railway volume delete pg-data"

    out = _run(runner, _shell_before(project, cmd), "--guard")
    assert out["permission"] == "deny" and out["continue"] is True
    assert "precondition" in out["user_message"] and out["agent_message"] == out["user_message"]

    monkeypatch.chdir(project)
    added = runner.invoke(cli, ["precondition", "add", "--scope", "pg-data", "--check", _ok_cmd()])
    assert added.exit_code == 0, added.output

    out = _run(runner, _shell_before(project, cmd, gen="gen-2"), "--guard")
    assert out == {"continue": True, "permission": "allow"}
    _run(runner, _shell_after(project, cmd, "deleted", gen="gen-2"))
    _run(runner, _stop(project))

    guards = [r.get("guard") for r in _recs(project) if r["kind"] == "pre"]
    assert guards[0] == {"decision": "deny", "rule": "paas.railway", "precondition": None}
    assert guards[1]["decision"] == "allow" and len(guards[1]["precondition"]) == 64
    rep = verify_session(_log(project))
    assert rep.valid, rep.errors
    assert rep.blocked == 1


def test_guard_denies_destructive_mcp_tool(project, home):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    out = _run(runner, _mcp_before(project, "volume_delete", {"volume": "pg-data"}), "--guard")
    assert out["permission"] == "deny" and "mcp.destructive-tool" in out["user_message"]
    (rec,) = _recs(project)
    assert rec["tool"] == "mcp__railway__volume_delete" and rec["guard"]["decision"] == "deny"


def test_guard_denies_reading_signing_key_and_ignores_normal_reads(project, home):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    read = {**_common("beforeReadFile", project), "file_path": str(project / "README.md"),
            "content": "hello", "attachments": []}
    assert _run(runner, read, "--guard") == {"permission": "allow"}
    assert not _log(project).exists()  # ordinary reads leave no receipt

    read["file_path"] = str(home / ".perathos" / "keys" / "signing.key")
    out = _run(runner, read, "--guard")
    assert out["permission"] == "deny" and set(out) == {"permission", "user_message"}
    assert _recs(project)[0]["guard"]["rule"] == "guard.key-access"


def test_safe_command_with_guard_has_no_guard_field(project, home):
    out = _run(CliRunner(), _shell_before(project, "git status"), "--guard")
    assert out["permission"] == "allow"
    assert "guard" not in _recs(project)[0]


def test_deny_survives_recorder_failure(project, home, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(cursor, "append_receipt", boom)
    seen = []
    out = cursor.run_hook(json.dumps(_shell_before(project, "rm -rf /data")), guard=True,
                          verify_key=lambda: None, warn=seen.append)
    assert out["permission"] == "deny"
    assert any("disk full" in m for m in seen)


def test_guard_without_flag_never_denies(project, home):
    out = _run(CliRunner(), _shell_before(project, "rm -rf /data"))
    assert out["permission"] == "allow"


# ── Robustness ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", ["", "not json", "[1, 2]", "null", '{"hook_event_name": 7}',
                                 '{"hook_event_name": "afterShellExecution", "workspace_roots": 5}'])
def test_malformed_stdin_never_crashes(raw, home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(cli, ["hooks", "record-cursor", "--guard"], input=raw)
    assert r.exit_code == 0
    assert isinstance(json.loads(r.stdout), dict)


def test_unknown_event_is_ignored(project, home):
    out = _run(CliRunner(), {**_common("afterAgentThought", project), "text": "hmm"})
    assert out == {}
    assert not _log(project).exists()


def test_anchor_failure_never_breaks_stop(project, home, monkeypatch):
    from perathos import anchor as anchor_mod

    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0

    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(anchor_mod, "request_timestamp", boom)
    r = runner.invoke(cli, ["hooks", "record-cursor", "--anchor"], input=json.dumps(_stop(project)))
    assert r.exit_code == 0 and json.loads(r.stdout) == {}
    assert "network down" in r.stderr
    assert _recs(project)[-1]["signature"]


# ── Install ──────────────────────────────────────────────────────────────────

def test_install_writes_hooks_json_and_preserves_others(tmp_path, home, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / ".cursor" / "hooks.json"
    cfg.parent.mkdir()
    cfg.write_text(json.dumps({"version": 1, "hooks": {
        "beforeShellExecution": [{"command": "./audit.sh", "timeout": 5}],
        "beforeSubmitPrompt": [{"command": "./redact.sh"}],
    }}), encoding="utf-8")

    runner = CliRunner()
    r = runner.invoke(cli, ["hooks", "install", "--agent", "cursor", "--guard", "--anchor"])
    assert r.exit_code == 0, r.output
    data = json.loads(cfg.read_text(encoding="utf-8"))
    hooks = data["hooks"]
    assert data["version"] == 1
    assert hooks["beforeSubmitPrompt"] == [{"command": "./redact.sh"}]
    assert hooks["beforeShellExecution"] == [
        {"command": "./audit.sh", "timeout": 5},
        {"command": "perathos hooks record-cursor --guard", "timeout": 10},
    ]
    assert hooks["beforeMCPExecution"][0]["command"] == "perathos hooks record-cursor --guard"
    assert hooks["beforeReadFile"][0]["command"] == "perathos hooks record-cursor --guard"
    assert hooks["afterShellExecution"][0]["command"] == "perathos hooks record-cursor"
    assert hooks["afterMCPExecution"][0]["command"] == "perathos hooks record-cursor"
    assert hooks["afterFileEdit"][0]["command"] == "perathos hooks record-cursor"
    assert hooks["stop"] == [{"command": "perathos hooks record-cursor --anchor", "timeout": 20}]
    assert hooks["sessionEnd"][0]["command"] == "perathos hooks record-cursor --anchor"
    assert not (tmp_path / ".claude").exists()  # Claude Code settings untouched

    # second install refuses without --force, and --force replaces only ours
    assert runner.invoke(cli, ["hooks", "install", "--agent", "cursor"]).exit_code == 1
    r = runner.invoke(cli, ["hooks", "install", "--agent", "cursor", "--force"])
    assert r.exit_code == 0, r.output
    hooks = json.loads(cfg.read_text(encoding="utf-8"))["hooks"]
    assert [e["command"] for e in hooks["beforeShellExecution"]] == ["./audit.sh", "perathos hooks record-cursor"]
    assert "beforeReadFile" not in hooks  # guard-only hook removed on reinstall without --guard
    assert hooks["stop"] == [{"command": "perathos hooks record-cursor", "timeout": 10}]


def test_install_user_scope(home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(cli, ["hooks", "install", "--agent", "cursor", "--scope", "user"])
    assert r.exit_code == 0, r.output
    data = json.loads((home / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
    assert data["version"] == 1 and "beforeShellExecution" in data["hooks"]
    assert not (tmp_path / ".cursor").exists()


def test_install_rejects_invalid_hooks_json(tmp_path, home, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "hooks.json").write_text("{nope", encoding="utf-8")
    r = CliRunner().invoke(cli, ["hooks", "install", "--agent", "cursor"])
    assert r.exit_code == 1 and "not valid JSON" in r.output
    assert (tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8") == "{nope"


def test_default_agent_is_still_claude_code(tmp_path, home, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert CliRunner().invoke(cli, ["hooks", "install", "--recorder"]).exit_code == 0
    assert (tmp_path / ".claude" / "settings.json").exists()
    assert not (tmp_path / ".cursor").exists()
