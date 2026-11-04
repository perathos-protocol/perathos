"""Guard hardening after the 1.0.0 red-team: accident-class commands, self-disable,
script scanning, scope matching, fail-closed hooks, unpinned-verify wording,
MCP batch requests."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.cli import cli
from perathos.guard import _covers, create_precondition, decide, evaluate, normalize_command
from perathos.signing import generate_keypair

DESTRUCTIVE = [
    "del /s /q data", "rmdir /s /q data", "rd /s /q data", "format D:",
    "rm -r build", "rm -r --force build", "rm -rfd build", "rm -Rf build", "rm --recursive build",
    "ri -Recurse -Force data", "Remove-Item -Recurse data", "rm -r data -Force",
    "git reset --hard HEAD~5", "git clean -fdx", "git checkout -- .", "git checkout .", "git branch -D main",
    "git stash drop", "git push --mirror origin",
    "find data -delete", "find . -name '*.db' -exec rm {} \\;",
    "truncate -s 0 prod.db", ": > prod.db", "dd if=/dev/zero of=prod.db bs=1M", "shred -u prod.db",
    "mv data /dev/null",
    "python -c \"import shutil; shutil.rmtree('data')\"",
    "node -e \"require('fs').rmSync('data',{recursive:true})\"", "npx rimraf data",
    "bash -c \"r\"\"m -rf data\"", "xargs rm -rf < list",
    "psql -c 'DROP/**/TABLE users'", "psql -c \"drop\ntable users\"",
    "aws s3 rm --recursive s3://backups",
]
SELF_PROTECT = [
    "cat ~/.perathos/k''eys/signing.key", "cat ~/.perathos/keys/signing.key", "type %USERPROFILE%\\.perathos\\keys\\signing.key",
    "echo '{}' > .claude/settings.json", "sed -i 's/perathos-hook//' .claude/settings.json",
    "rm .perathos/sessions/abc.jsonl", "cp old.json .perathos/preconditions/x.json",
    "perathos precondition add --scope '*' --manual ok", "perathos keygen",
]
SAFE = [
    "ls -la", "rm notes.txt", "rm -f build.log", "git push origin feature/x", "git status", "git checkout feature/x",
    "git checkout -b new", "git branch -d merged-branch", "git stash", "psql -c 'delete from users where id = 4'",
    "pytest -q", "terraform plan", "kubectl get pods", "cat .claude/settings.json", "perathos session verify abc",
    "ls .perathos/sessions", "echo hello > out.txt", "python -c 'print(1)'", "node -e 'console.log(1)'",
    "find . -name '*.py'", "docker ps", "npm run build", "rm -i temp.txt", "git log --oneline",
    "truncate -s 100 file.bin", "dd if=disk.img of=/dev/null bs=1M count=1",
]


@pytest.mark.parametrize("cmd", DESTRUCTIVE)
def test_destructive_blocked(cmd):
    m = evaluate("Bash", {"command": cmd})
    assert m is not None and not m.self_auth, cmd


@pytest.mark.parametrize("cmd", SELF_PROTECT)
def test_self_protection(cmd):
    m = evaluate("Bash", {"command": cmd})
    assert m is not None and m.self_auth, cmd


@pytest.mark.parametrize("cmd", SAFE)
def test_safe_allowed(cmd):
    assert evaluate("Bash", {"command": cmd}) is None, cmd


def test_normalize_strips_quotes_and_comments():
    assert normalize_command("r\"\"m -rf x") == "rm -rf x"
    assert normalize_command("DROP/**/TABLE t") == "DROP TABLE t"


def test_file_tools_self_protection_and_script_writes():
    assert evaluate("Edit", {"file_path": "/p/.claude/settings.json", "old_string": "a", "new_string": ""}).self_auth
    assert evaluate("Write", {"file_path": "/p/.cursor/hooks.json", "content": "{}"}).self_auth
    assert evaluate("Write", {"file_path": "/p/.perathos/preconditions/x.json", "content": "{}"}).self_auth
    assert evaluate("Read", {"file_path": "/h/.perathos/keys/signing.key"}).self_auth
    assert evaluate("Read", {"file_path": "/p/.claude/settings.json"}) is None  # reading is fine
    m = evaluate("Write", {"file_path": "/p/wipe.sh", "content": "#!/bin/sh\nrm -rf /data\n"})
    assert m is not None and m.rule_id == "write:fs.rm-recursive"
    assert evaluate("Write", {"file_path": "/p/README.md", "content": "run rm -rf build to clean"}) is None
    assert evaluate("Write", {"file_path": "/p/app.py", "content": "print('hi')"}) is None


def test_script_files_are_scanned(tmp_path):
    (tmp_path / "wipe.sh").write_text("rm -rf /data\n", encoding="utf-8")
    (tmp_path / "evil.sql").write_text("-- cleanup\nDROP TABLE users;\n", encoding="utf-8")
    (tmp_path / "fine.sh").write_text("echo ok\n", encoding="utf-8")
    for cmd in ("bash wipe.sh", "./wipe.sh", "sh ./wipe.sh", "psql -U app -f evil.sql"):
        m = evaluate("Bash", {"command": cmd}, tmp_path)
        assert m is not None and m.rule_id.startswith("script:"), cmd
    assert evaluate("Bash", {"command": "bash fine.sh"}, tmp_path) is None
    assert evaluate("Bash", {"command": "bash wipe.sh"}) is None  # no cwd: cannot scan, documented


def test_scope_matches_whole_tokens():
    assert _covers("build", "rm -rf build")
    assert _covers("build", "rm -rf ./build/")
    assert not _covers("build", "rm -rf /var/lib/postgres-build-data")
    assert _covers("pg-data", "railway volume delete pg-data --yes")
    assert _covers("*", "anything")


def test_decide_passes_cwd_for_script_scan(tmp_path):
    _, vk = generate_keypair()
    (tmp_path / "wipe.sh").write_text("rm -rf /data\n", encoding="utf-8")
    d = decide("Bash", {"command": "bash wipe.sh"}, tmp_path, trusted_key=vk)
    assert d is not None and d.decision == "deny"
    sk, vk = generate_keypair()
    create_precondition(tmp_path, scope="*", signing_key_hex=sk, manual_reason="ok")
    assert decide("Bash", {"command": "bash wipe.sh"}, tmp_path, trusted_key=vk).decision == "allow"


# ── fail-closed hooks ────────────────────────────────────────────────────────

def test_claude_code_guard_hook_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert CliRunner().invoke(cli, ["hooks", "install", "--guard"]).exit_code == 0
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    pre = hooks["PreToolUse"][0]["hooks"][0]
    assert pre["onFailure"] == "block"
    assert "onFailure" not in hooks["PostToolUse"][0]["hooks"][0]


def test_cursor_guard_hook_is_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(cli, ["hooks", "install", "--agent", "cursor", "--guard"])
    assert r.exit_code == 0, r.output
    cfg = json.loads((tmp_path / ".cursor" / "hooks.json").read_text(encoding="utf-8"))
    guarded = [e for ev in cfg["hooks"].values() for e in ev if "--guard" in e["command"]]
    assert guarded and all(e.get("failClosed") is True for e in guarded)


def test_managed_scope_sets_allow_managed_hooks_only(tmp_path, monkeypatch):
    import perathos.cli as cli_mod
    target = tmp_path / "managed" / "managed-settings.json"
    monkeypatch.setattr(cli_mod, "_managed_settings_path", lambda: target)
    r = CliRunner().invoke(cli, ["hooks", "install", "--scope", "managed", "--guard"])
    assert r.exit_code == 0, r.output
    settings = json.loads(target.read_text(encoding="utf-8"))
    assert settings["allowManagedHooksOnly"] is True
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "perathos-hook record --guard"


# ── unpinned verify wording ──────────────────────────────────────────────────

def test_unpinned_verify_flags_unconfirmed_signer(tmp_path, monkeypatch):
    from perathos.recorder import record_hook_event
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    vk = (tmp_path / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    sk = (tmp_path / ".perathos" / "keys" / "signing.key").read_text(encoding="utf-8").strip()
    record_hook_event({"hook_event_name": "PreToolUse", "session_id": "u1", "cwd": str(tmp_path),
                       "tool_name": "Bash", "tool_use_id": "a", "tool_input": {"command": "ls"}})
    record_hook_event({"hook_event_name": "Stop", "session_id": "u1", "cwd": str(tmp_path)}, signing_key_hex=sk)
    unpinned = runner.invoke(cli, ["session", "verify", "u1"])
    assert unpinned.exit_code == 0 and "VALID_UNCONFIRMED_SIGNER" in unpinned.output and "confirm this" in unpinned.output
    pinned = runner.invoke(cli, ["session", "verify", "u1", "--verify-key", vk])
    assert pinned.exit_code == 0 and pinned.output.startswith("VALID  ")
    exp = runner.invoke(cli, ["session", "export", "u1", "--out", str(tmp_path / "pack")])
    assert exp.exit_code == 0, exp.output
    ev = runner.invoke(cli, ["evidence", "verify", str(tmp_path / "pack.zip")])
    assert ev.exit_code == 0 and "VALID_UNCONFIRMED_SIGNER" in ev.output
    ev = runner.invoke(cli, ["evidence", "verify", str(tmp_path / "pack.zip"), "--verify-key", vk])
    assert ev.exit_code == 0 and ev.output.startswith("VALID  ")


# ── MCP batch requests ───────────────────────────────────────────────────────

BATCH_SERVER = """
import json, sys

def handle(msg):
    res = {"content": [{"type": "text", "text": "ran " + json.dumps(msg["params"].get("arguments"))}]}
    return {"jsonrpc": "2.0", "id": msg["id"], "result": res}

for line in sys.stdin:
    parsed = json.loads(line)
    if isinstance(parsed, list):
        print(json.dumps([handle(m) for m in parsed if "id" in m]), flush=True)
    elif "id" in parsed:
        print(json.dumps(handle(parsed)), flush=True)
"""


def test_mcp_proxy_batch_requests_are_recorded_and_guarded(tmp_path):
    from perathos.recorder import session_log_path, verify_session
    import os

    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    subprocess.run([sys.executable, "-m", "perathos", "keygen"], env=env, check=True, capture_output=True)
    server = tmp_path / "fake_server.py"
    # Batch-aware fake server: answers each request in a batch with a batch response.
    server.write_text(BATCH_SERVER, encoding="utf-8")
    project = tmp_path / "proj"
    project.mkdir()
    batch = json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "query", "arguments": {"sql": "DROP TABLE users"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "query", "arguments": {"sql": "select 1"}}},
    ])
    cmd = [sys.executable, "-m", "perathos", "mcp-proxy", "--name", "db", "--session", "b1", "--project", str(project),
           "--guard", "--", sys.executable, str(server)]
    r = subprocess.run(cmd, input=batch + "\n", text=True, capture_output=True, env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    out = [json.loads(x) for x in r.stdout.splitlines() if x.strip()]
    denies = [m for chunk in out for m in (chunk if isinstance(chunk, list) else [chunk]) if m.get("id") == 1]
    assert denies and denies[0]["result"]["isError"] is True
    rep = verify_session(session_log_path(project, "b1"))
    assert rep.valid, rep.errors
    assert rep.tool_calls == 2 and rep.blocked == 1
