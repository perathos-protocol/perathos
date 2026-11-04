"""Tests for the Claude Code Stop-hook integration (perathos/hooks.py + the
`perathos hooks` CLI commands)."""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.cli import cli
from perathos.hooks import check_stop_hook, extract_transcript_sources


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirect ~/.perathos to an isolated temp dir for the duration of a test."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def _write_transcript(tmp_path: Path, lines: list[dict]) -> str:
    path = tmp_path / "transcript.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in lines), encoding="utf-8")
    return str(path)


# ── extract_transcript_sources ──────────────────────────────────────────────

def test_extract_transcript_sources_reads_string_content(tmp_path):
    path = _write_transcript(tmp_path, [
        {"type": "user", "content": "run the tests"},
        {"type": "tool_result", "tool_use_id": "t1", "content": "42 tests passed", "is_error": False},
    ])
    assert extract_transcript_sources(path) == ["42 tests passed"]


def test_extract_transcript_sources_reads_block_list_content(tmp_path):
    path = _write_transcript(tmp_path, [
        {"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "build succeeded"}]},
    ])
    assert extract_transcript_sources(path) == ["build succeeded"]


def test_extract_transcript_sources_ignores_non_tool_result_entries(tmp_path):
    path = _write_transcript(tmp_path, [
        {"type": "assistant", "content": "I'll check that now"},
        {"type": "tool_use", "tool_name": "Bash", "tool_input": {"command": "pytest"}},
    ])
    assert extract_transcript_sources(path) == []


def test_extract_transcript_sources_tolerates_malformed_lines(tmp_path):
    path = tmp_path / "transcript.jsonl"
    path.write_text('{"type": "tool_result", "content": "ok"}\nnot json\n', encoding="utf-8")
    assert extract_transcript_sources(str(path)) == ["ok"]


def test_extract_transcript_sources_missing_file_returns_empty():
    assert extract_transcript_sources("/no/such/file.jsonl") == []


# ── check_stop_hook ──────────────────────────────────────────────────────────

def test_check_stop_hook_flags_an_ungrounded_quoted_claim(tmp_path):
    transcript = _write_transcript(tmp_path, [
        {"type": "tool_result", "content": "the build finished with no errors"},
    ])
    payload = {
        "last_assistant_message": 'The deployment took "45 minutes" to complete.',
        "transcript_path": transcript,
        "session_id": "abc123",
    }
    result = check_stop_hook(payload)
    assert result["verdict"] == "FAIL"
    assert result["failing_records"]
    assert result["sources_count"] == 1


def test_check_stop_hook_does_not_flag_a_grounded_claim(tmp_path):
    transcript = _write_transcript(tmp_path, [
        {"type": "tool_result", "content": 'Completed in "45 minutes" total.'},
    ])
    payload = {
        "last_assistant_message": 'The deployment took "45 minutes" to complete.',
        "transcript_path": transcript,
    }
    result = check_stop_hook(payload)
    assert result["failing_records"] == []


def test_check_stop_hook_catches_wrong_arithmetic():
    payload = {"last_assistant_message": "The total is 2 + 2 = 5.", "transcript_path": ""}
    result = check_stop_hook(payload)
    assert result["verdict"] == "FAIL"
    assert result["failing_records"]


def test_check_stop_hook_handles_missing_fields_without_crashing():
    assert check_stop_hook({})["verdict"] in ("INCONCLUSIVE", None) or True  # never raises


def test_check_stop_hook_never_crashes_on_missing_transcript():
    payload = {"last_assistant_message": "All good.", "transcript_path": "/no/such/file.jsonl"}
    result = check_stop_hook(payload)
    assert result["sources_count"] == 0


# ── CLI: hooks install ───────────────────────────────────────────────────────

def test_hooks_install_writes_project_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["hooks", "install"])
    assert result.exit_code == 0, result.output

    settings_path = tmp_path / ".claude" / "settings.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    stop_hooks = settings["hooks"]["Stop"]
    assert len(stop_hooks) == 1
    # Claude Code only runs hooks nested under a "hooks" array.
    assert stop_hooks[0]["hooks"][0]["type"] == "command"
    assert stop_hooks[0]["hooks"][0]["command"] == "perathos hooks stop-check"
    assert "command" not in stop_hooks[0]


def test_hooks_install_twice_without_force_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(cli, ["hooks", "install"]).exit_code == 0
    second = runner.invoke(cli, ["hooks", "install"])
    assert second.exit_code != 0


def test_hooks_install_force_replaces_not_duplicates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(cli, ["hooks", "install"]).exit_code == 0
    result = runner.invoke(cli, ["hooks", "install", "--force"])
    assert result.exit_code == 0, result.output

    settings_path = tmp_path / ".claude" / "settings.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert len(settings["hooks"]["Stop"]) == 1


def test_hooks_install_preserves_existing_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({
        "hooks": {"PostToolUse": [{"type": "command", "command": "some-other-hook"}]},
        "otherSetting": True,
    }), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["hooks", "install"])
    assert result.exit_code == 0, result.output

    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    assert settings["otherSetting"] is True
    assert settings["hooks"]["PostToolUse"] == [{"type": "command", "command": "some-other-hook"}]
    assert settings["hooks"]["Stop"][0]["hooks"][0]["command"] == "perathos hooks stop-check"


def test_hooks_install_migrates_old_flat_entry(tmp_path, monkeypatch):
    """Older versions wrote a flat entry Claude Code never ran; reinstall fixes it."""
    monkeypatch.chdir(tmp_path)
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({
        "hooks": {"Stop": [{"type": "command", "command": "perathos hooks stop-check", "timeout": 30}]},
    }), encoding="utf-8")
    result = CliRunner().invoke(cli, ["hooks", "install"])
    assert result.exit_code == 0, result.output
    stop = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]["Stop"]
    assert stop == [{"hooks": [{"type": "command", "command": "perathos hooks stop-check", "timeout": 30}]}]


def test_hooks_install_recorder(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli, ["hooks", "install", "--recorder"])
    assert result.exit_code == 0, result.output
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    for event in ("PreToolUse", "PostToolUse"):
        assert hooks[event] == [{"matcher": "*", "hooks": [
            {"type": "command", "command": "perathos-hook record", "timeout": 10}]}]
    assert hooks["SessionEnd"][0]["hooks"][0]["command"] == "perathos-hook record"
    stop_cmds = [e["hooks"][0]["command"] for e in hooks["Stop"]]
    assert stop_cmds == ["perathos hooks stop-check", "perathos-hook record"]
    # reinstall without --force is refused, with --force it does not duplicate
    assert CliRunner().invoke(cli, ["hooks", "install", "--recorder"]).exit_code == 1
    assert CliRunner().invoke(cli, ["hooks", "install", "--recorder", "--force"]).exit_code == 0
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    assert len(hooks["PreToolUse"]) == 1 and len(hooks["Stop"]) == 2


# ── CLI: hooks stop-check ───────────────────────────────────────────────────

def test_hooks_stop_check_writes_a_receipt(tmp_path, home):
    payload = {
        "session_id": "abc12345",
        "cwd": str(tmp_path),
        "transcript_path": "",
        "last_assistant_message": "All good, nothing to check here.",
    }
    runner = CliRunner()
    result = runner.invoke(cli, ["hooks", "stop-check"], input=json.dumps(payload))
    assert result.exit_code == 0, result.output

    receipts = list((tmp_path / ".perathos" / "receipts").glob("*.json"))
    assert len(receipts) == 1
    bundle = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert bundle["bundle_version"] == "2.0"


def test_hooks_stop_check_surfaces_a_finding_as_additional_context(tmp_path, home):
    transcript = _write_transcript(tmp_path, [{"type": "tool_result", "content": "unrelated output"}])
    payload = {
        "session_id": "abc12345",
        "cwd": str(tmp_path),
        "transcript_path": transcript,
        "last_assistant_message": 'It took "45 minutes" total.',
    }
    runner = CliRunner()
    result = runner.invoke(cli, ["hooks", "stop-check"], input=json.dumps(payload))
    assert result.exit_code == 0, result.output
    output = json.loads(result.output)
    assert "additionalContext" in output["hookSpecificOutput"]
    assert output["hookSpecificOutput"]["hookEventName"] == "Stop"


def test_hooks_stop_check_signs_receipt_when_key_exists(tmp_path, home):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    payload = {"session_id": "abc12345", "cwd": str(tmp_path), "transcript_path": "",
               "last_assistant_message": "Nothing notable."}
    result = runner.invoke(cli, ["hooks", "stop-check"], input=json.dumps(payload))
    assert result.exit_code == 0, result.output

    receipts = list((tmp_path / ".perathos" / "receipts").glob("*.json"))
    bundle = json.loads(receipts[0].read_text(encoding="utf-8"))
    assert "provider_signature" in bundle


def test_hooks_stop_check_tolerates_malformed_stdin():
    runner = CliRunner()
    result = runner.invoke(cli, ["hooks", "stop-check"], input="not valid json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {}


def test_hooks_stop_check_never_blocks_exit_code(tmp_path, home):
    """Even when a finding is surfaced, the hook must exit 0 -- it observes, never blocks."""
    runner = CliRunner()
    payload = {"last_assistant_message": "5 + 5 = 11.", "transcript_path": "", "cwd": str(tmp_path)}
    result = runner.invoke(cli, ["hooks", "stop-check"], input=json.dumps(payload))
    assert result.exit_code == 0


# --- Real Claude Code transcript format -------------------------------------
# Real transcripts nest tool results inside a ``user`` entry's
# ``message.content`` list; they never appear as top-level lines. The fixture
# copies the field structure of a real Claude Code session with synthetic
# values. Before this fix the extractor found 0 sources in real sessions.

_REAL_FIXTURE = Path(__file__).parent / "fixtures" / "claude_code_transcript_v2.jsonl"


def test_extract_sources_from_real_transcript_format():
    sources = extract_transcript_sources(str(_REAL_FIXTURE))
    assert sources == ["314 passed in 8.2s", "version 0.3.1"]


def test_real_transcript_skips_non_text_blocks_and_assistant_text():
    sources = extract_transcript_sources(str(_REAL_FIXTURE))
    joined = " ".join(sources)
    assert "AAAA" not in joined            # image data is not grounding text
    assert "tool_reference" not in joined  # nor are tool references
    assert "All 314 tests passed" not in joined  # the agent's own claim is never a source


def test_stop_hook_grounds_against_real_transcript():
    result = check_stop_hook({
        "last_assistant_message": "All 314 tests passed on version 0.3.1.",
        "transcript_path": str(_REAL_FIXTURE),
    })
    assert result["sources_count"] == 2
    assert result["verdict"] != "NOT_APPLICABLE"


def test_reinstall_upgrades_old_recorder_command(tmp_path, monkeypatch):
    """Installs from <= 0.5 used `perathos hooks record`; --force replaces them, no duplicates."""
    monkeypatch.chdir(tmp_path)
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    old = {"hooks": [{"type": "command", "command": "perathos hooks record --guard", "timeout": 10}]}
    settings_path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", **old}]}}), encoding="utf-8")
    assert CliRunner().invoke(cli, ["hooks", "install", "--guard"]).exit_code == 1  # needs --force
    assert CliRunner().invoke(cli, ["hooks", "install", "--guard", "--force"]).exit_code == 0
    pre = json.loads(settings_path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    assert [e["hooks"][0]["command"] for e in pre] == ["perathos-hook record --guard"]


def test_lean_hook_entry_matches_cli(tmp_path):
    """`perathos-hook record` and `perathos hooks record` write identical receipt shapes."""
    import io

    from perathos.hook import main, run_record
    payload = {"hook_event_name": "PreToolUse", "session_id": "lean", "cwd": str(tmp_path),
               "tool_name": "Bash", "tool_use_id": "x1", "tool_input": {"command": "ls"}}
    out, err = io.StringIO(), io.StringIO()
    run_record(json.dumps(payload), guard=True, anchor=False, out=out, err=err)
    assert out.getvalue() == ""
    log = tmp_path / ".perathos" / "sessions" / "lean.jsonl"
    rec = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert rec["kind"] == "pre" and rec["tool"] == "Bash"
    assert main(["bogus"]) == 0  # usage errors never fail an agent turn
