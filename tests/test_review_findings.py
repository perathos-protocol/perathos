"""Threat-model review fixes: Gate approvals in evidence packs are pinned and cross-checked,
the MCP proxy guard fails closed, a signer failure is marked on the checkpoint, and
recording failures leave a trace in the local error log."""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.cli import cli
from perathos.errlog import errors_log_path, log_error, read_errors
from perathos.evidence import export_evidence_pack, verify_evidence_pack
from perathos.gate import apply_gate
from perathos.hook import run_record
from perathos.mcp_proxy import McpRecorder
from perathos.recorder import append_receipt, content_hash, record_hook_event, session_log_path, verify_session
from perathos.signing import generate_keypair

from .test_gate import ARGS, DENY, _login
from .test_gate import gate  # noqa: F401 -- pytest fixture (stub Gate server with a software passkey)


# --------------------------------------------------------------------------- #
# 1. evidence verify: Gate key, approver pins, cross-check against the log
# --------------------------------------------------------------------------- #

def _approved_pack(gate, tmp_path, *, tamper=None):  # noqa: F811
    """A session whose one destructive call was approved through the Gate, exported as a pack."""
    _login(gate)
    sk, vk = generate_keypair()
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    gate.decide(gate.only_pending(), "approve")
    payload = {"hook_event_name": "PreToolUse", "session_id": "e1", "cwd": str(tmp_path), "tool_name": "Bash",
               "tool_use_id": "t1", "tool_input": ARGS}
    run_record(json.dumps(payload), guard=True, anchor=False, out=io.StringIO(), err=io.StringIO())
    if tamper:
        tamper(session_log_path(tmp_path, "e1"))
    record_hook_event({"hook_event_name": "Stop", "session_id": "e1", "cwd": str(tmp_path)}, signing_key_hex=sk)
    res = export_evidence_pack(session_log_path(tmp_path, "e1"), tmp_path / "pack", signing_key_hex=sk)
    saved = list((tmp_path / ".perathos" / "approvals").glob("apr_*.json"))
    return res, vk, json.loads(saved[0].read_text(encoding="utf-8")) if saved else None


def _auditor_machine(tmp_path, monkeypatch):
    """A machine with no Perathos config: nothing pinned."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "auditor-home"))
    monkeypatch.delenv("PERATHOS_GATE_APPROVERS", raising=False)


def test_evidence_verify_reports_unconfirmed_gate_and_unpinned_approvers(gate, tmp_path, monkeypatch):  # noqa: F811
    res, vk, receipt = _approved_pack(gate, tmp_path)
    # On the operator's machine the Gate key is pinned (gate login); no approver is.
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk)
    assert out["valid"] and out["approvals"]["gate_key_confirmed"] and out["approvals"]["gate_key_source"] == "local pin"
    assert out["approvals"]["approvers_pinned"] is False

    _auditor_machine(tmp_path, monkeypatch)
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk)
    ap = out["approvals"]
    assert out["valid"], out["errors"]
    assert ap["cited"] == 1 and ap["verified"] == 1 and ap["in_pack"] == 1
    assert ap["gate_key_confirmed"] is False and ap["approvers_pinned"] is False
    assert ap["gate_keys"] == [gate.server_vk] and ap["approvers"][0]["name"] == "Alice Moyo"

    runner = CliRunner()
    r = runner.invoke(cli, ["evidence", "verify", str(res["dir"]), "--verify-key", vk])
    assert r.exit_code == 0, r.output
    assert r.output.startswith("VALID_UNCONFIRMED_GATE ")
    assert "approvals    1 cited, 1 verified, Gate key UNCONFIRMED, approvers NOT PINNED" in r.output
    # Without a signer pin either, the first word still does not read as a clean VALID.
    r = runner.invoke(cli, ["evidence", "verify", str(res["dir"])])
    assert r.output.startswith("VALID_UNCONFIRMED_SIGNER ") and "Gate key UNCONFIRMED" in r.output

    pub = receipt["approver"]["public_key"]
    r = runner.invoke(cli, ["evidence", "verify", str(res["dir"]), "--verify-key", vk,
                            "--gate-key", gate.server_vk, "--approver-key", pub])
    assert r.exit_code == 0, r.output
    assert r.output.startswith("VALID ")
    assert "Gate key confirmed (argument), approvers pinned (argument)" in r.output
    as_json = json.loads(runner.invoke(cli, ["evidence", "verify", str(res["dir"]), "--json",
                                             "--gate-key", gate.server_vk]).output)
    assert as_json["approvals"]["gate_key_confirmed"] is True and as_json["approvals"]["approvers_pinned"] is False


def test_evidence_verify_rejects_wrong_gate_key_and_unpinned_approver(gate, tmp_path, monkeypatch):  # noqa: F811
    res, vk, _ = _approved_pack(gate, tmp_path)
    _auditor_machine(tmp_path, monkeypatch)
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk, gate_key="ab" * 32)
    assert not out["valid"] and any(e.startswith("ERR_GATE_UNEXPECTED_SERVER") for e in out["errors"])
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk, gate_key=gate.server_vk,
                               approver_keys=["bm90LXRoZS1rZXk"])
    assert not out["valid"] and any(e.startswith("ERR_GATE_UNTRUSTED_APPROVER") for e in out["errors"])
    r = CliRunner().invoke(cli, ["evidence", "verify", str(res["dir"]), "--verify-key", vk, "--gate-key", "ab" * 32])
    assert r.exit_code == 1 and r.output.startswith("INVALID ")


def test_evidence_verify_uses_local_pins_unless_told_not_to(gate, tmp_path, monkeypatch):  # noqa: F811
    res, vk, receipt = _approved_pack(gate, tmp_path)
    monkeypatch.setenv("PERATHOS_GATE_APPROVERS", receipt["approver"]["public_key"])
    ap = verify_evidence_pack(res["dir"], expected_verify_key=vk)["approvals"]
    assert ap["gate_key_confirmed"] and ap["approvers_pinned"] and ap["approvers_source"] == "local pin"
    ap = verify_evidence_pack(res["dir"], expected_verify_key=vk, use_local_pins=False)["approvals"]
    assert not ap["gate_key_confirmed"] and not ap["approvers_pinned"]
    # A locally pinned approver that is not the one in the pack fails the pack.
    monkeypatch.setenv("PERATHOS_GATE_APPROVERS", "c29tZW9uZS1lbHNl")
    assert not verify_evidence_pack(res["dir"], expected_verify_key=vk)["valid"]


def test_cited_approval_missing_from_pack(gate, tmp_path):  # noqa: F811
    def lose_receipts(_log):
        for f in (tmp_path / ".perathos" / "approvals").glob("apr_*.json"):
            f.unlink()
    res, vk, _ = _approved_pack(gate, tmp_path, tamper=lose_receipts)
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk)
    assert not out["valid"]
    assert [e.split(":")[0] for e in out["errors"]] == ["ERR_APPROVAL_MISSING"]
    assert out["approvals"]["cited"] == 1 and out["approvals"]["verified"] == 0


def test_cited_approval_for_different_arguments(gate, tmp_path):  # noqa: F811
    """A second call, with other arguments, pointing at the same approval."""
    def reuse(log):
        first = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        append_receipt(log, {"session_id": "e1", "agent": "claude-code", "kind": "pre", "tool": "Bash",
                             "tool_use_id": "t2", "args_hash": content_hash({"command": "dropdb customers"}),
                             "guard": dict(first["guard"])})
    res, vk, _ = _approved_pack(gate, tmp_path, tamper=reuse)
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk)
    assert not out["valid"]
    assert [e.split(":")[0] for e in out["errors"]] == ["ERR_APPROVAL_ARGS_MISMATCH"]
    assert "receipt 2 " in out["errors"][0]
    assert out["approvals"]["cited"] == 2 and out["approvals"]["verified"] == 1
    assert any("used once" in w for w in out["warnings"])


def test_cited_approval_that_is_a_denial(gate, tmp_path):  # noqa: F811
    _login(gate)
    sk, vk = generate_keypair()
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    gate.decide(gate.only_pending(), "deny")
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)  # fetches and saves the denial
    denial = json.loads(next((tmp_path / ".perathos" / "approvals").glob("apr_*.json")).read_text(encoding="utf-8"))
    assert denial["decision"] == "deny"
    log = session_log_path(tmp_path, "e2")
    append_receipt(log, {"session_id": "e2", "agent": "claude-code", "kind": "pre", "tool": "Bash",
                         "tool_use_id": "t1", "args_hash": content_hash(ARGS),
                         "guard": {"decision": "allow", "rule": "db.dropdb", "precondition": None,
                                   "approval": denial["receipt_hash"]}})
    record_hook_event({"hook_event_name": "Stop", "session_id": "e2", "cwd": str(tmp_path)}, signing_key_hex=sk)
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=sk)
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk)
    assert [e.split(":")[0] for e in out["errors"]] == ["ERR_APPROVAL_NOT_APPROVED"]


def test_cursor_shell_approval_binds_the_hash_the_receipt_records(gate, tmp_path):  # noqa: F811
    """Cursor shell receipts hash the command string; the approval must be for that same hash."""
    from perathos.integrations.cursor import run_hook
    _login(gate)
    sk, vk = generate_keypair()
    payload = {"hook_event_name": "beforeShellExecution", "conversation_id": "c1", "generation_id": "g1",
               "workspace_roots": [str(tmp_path)], "command": "dropdb prod", "cwd": str(tmp_path)}
    assert run_hook(json.dumps(payload), guard=True)["permission"] == "deny"
    gate.decide(gate.only_pending(), "approve")
    assert run_hook(json.dumps(payload), guard=True)["permission"] == "allow"
    run_hook(json.dumps({"hook_event_name": "stop", "conversation_id": "c1", "workspace_roots": [str(tmp_path)]}),
             load_signing_key=lambda: sk)
    log = session_log_path(tmp_path, "c1")
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=sk)
    out = verify_evidence_pack(res["dir"], expected_verify_key=vk)
    assert out["valid"], out["errors"]
    assert out["approvals"]["verified"] == 1


# --------------------------------------------------------------------------- #
# 2. MCP proxy: the guard fails closed
# --------------------------------------------------------------------------- #

def _call(i, sql="select 1"):
    msg = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "query", "arguments": {"sql": sql}}}
    if i is not None:
        msg["id"] = i
    return msg


def _broken_guard(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("rules file unreadable")
    monkeypatch.setattr("perathos.guard.decide", boom)


def test_mcp_proxy_guard_crash_denies_and_records(tmp_path, monkeypatch):
    _broken_guard(monkeypatch)
    rec = McpRecorder(name="db", project=tmp_path, session_id="s1", guard=True)
    reply = rec.on_tools_call(_call(7))
    assert reply["id"] == 7 and reply["result"]["isError"] is True
    text = reply["result"]["content"][0]["text"]
    assert "guard itself failed" in text and "RuntimeError" in text and "fails closed" in text
    assert rec.pending == {}  # never forwarded, so no result is expected
    receipt = json.loads(rec.log.read_text(encoding="utf-8").splitlines()[0])
    assert receipt["guard"] == {"decision": "deny", "rule": "guard.error", "precondition": None}
    assert any(e.startswith("guard: RuntimeError") for e in rec.errors)
    rep = verify_session(rec.log, require_signed=False)
    assert rep.blocked == 1


def test_mcp_proxy_guard_crash_denies_even_if_recording_fails(tmp_path, monkeypatch):
    _broken_guard(monkeypatch)
    monkeypatch.setattr("perathos.mcp_proxy.append_receipt", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    rec = McpRecorder(name="db", project=tmp_path, session_id="s1", guard=True)
    assert rec.on_tools_call(_call(1))["result"]["isError"] is True
    assert [e["component"] for e in read_errors(session_id="s1")] == ["mcp-proxy.record"]


def test_mcp_proxy_without_guard_is_unchanged(tmp_path, monkeypatch):
    _broken_guard(monkeypatch)  # never consulted when the guard is off
    rec = McpRecorder(name="db", project=tmp_path, session_id="s1", guard=False)
    assert rec.on_tools_call(_call(1, "DROP TABLE users")) is None
    assert len(rec.pending) == 1
    assert "guard" not in json.loads(rec.log.read_text(encoding="utf-8").splitlines()[0])


FAKE_SERVER = '''
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    for m in (msg if isinstance(msg, list) else [msg]):
        with open(sys.argv[1], "a") as fh:
            fh.write(json.dumps(m) + "\\n")
    out = [{"jsonrpc": "2.0", "id": m["id"], "result": {"content": []}}
           for m in (msg if isinstance(msg, list) else [msg]) if "id" in m]
    if out:
        print(json.dumps(out if isinstance(msg, list) else out[0]), flush=True)
'''


def _proxy(tmp_path, lines, *, guard):
    """Run the relay loop in-process against a server that logs every message it receives."""
    from perathos.mcp_proxy import run_proxy
    server = tmp_path / "server.py"
    server.write_text(FAKE_SERVER, encoding="utf-8")
    seen = tmp_path / "seen.jsonl"
    seen.write_text("", encoding="utf-8")
    rec = McpRecorder(name="db", project=tmp_path / "proj", session_id="s1", guard=guard)
    out = io.BytesIO()
    run_proxy([sys.executable, str(server), str(seen)], rec,
              stdin=io.BytesIO(("\n".join(json.dumps(x) for x in lines) + "\n").encode()), stdout=out)
    received = [json.loads(x) for x in seen.read_text(encoding="utf-8").splitlines()]
    replies = []
    for line in out.getvalue().decode().splitlines():
        parsed = json.loads(line)
        replies.extend(parsed if isinstance(parsed, list) else [parsed])
    return received, {r["id"]: r for r in replies}, rec


def test_mcp_proxy_guards_each_call_in_a_batch(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    batch = [_call(1, "DROP TABLE users"), _call(2, "select 1"), {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}]
    received, replies, rec = _proxy(tmp_path, [batch], guard=True)
    assert sorted(m["id"] for m in received) == [2, 3]  # the destructive call never reached the server
    assert replies[1]["result"]["isError"] is True and "result" in replies[2] and "result" in replies[3]
    assert verify_session(rec.log, require_signed=False).blocked == 1


def test_mcp_proxy_batch_fails_closed_when_the_guard_crashes(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    _broken_guard(monkeypatch)
    batch = [_call(1), _call(2), {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}]
    received, replies, _ = _proxy(tmp_path, [batch, _call(4)], guard=True)
    assert [m["id"] for m in received] == [3]
    assert all(replies[i]["result"]["isError"] is True for i in (1, 2, 4))


def test_mcp_proxy_guards_a_tools_call_sent_as_a_notification(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    lines = [_call(None, "DROP TABLE users"), _call(None, "select 1"), _call(5, "select 2")]
    received, replies, rec = _proxy(tmp_path, lines, guard=True)
    sqls = [m["params"]["arguments"]["sql"] for m in received]
    assert sqls == ["select 1", "select 2"]  # the denied notification was dropped, not forwarded
    assert set(replies) == {5}
    assert verify_session(rec.log, require_signed=False).blocked == 1
    # Guard off: notifications are relayed untouched and not recorded, as before.
    (tmp_path / "proj2").mkdir()
    received, _, _ = _proxy(tmp_path, [_call(None, "DROP TABLE users")], guard=False)
    assert len(received) == 1


# --------------------------------------------------------------------------- #
# 3. A signer failure is marked on the checkpoint and surfaced by the verifier
# --------------------------------------------------------------------------- #

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("PERATHOS_SIGNER", raising=False)
    return tmp_path / "home"


def _tool_call(cwd, sid):
    record_hook_event({"hook_event_name": "PreToolUse", "session_id": sid, "cwd": str(cwd), "tool_name": "Bash",
                       "tool_use_id": "t1", "tool_input": {"command": "ls"}})


def test_unreachable_remote_signer_marks_the_checkpoint(home, tmp_path, monkeypatch):
    monkeypatch.setenv("PERATHOS_SIGNER", "command:definitely-not-a-real-signer-binary")
    _tool_call(tmp_path, "sf1")
    err = io.StringIO()
    run_record(json.dumps({"hook_event_name": "Stop", "session_id": "sf1", "cwd": str(tmp_path)}),
               guard=False, anchor=False, out=io.StringIO(), err=err)
    assert "WARNING" in err.getvalue() and "UNSIGNED" in err.getvalue()
    log = session_log_path(tmp_path, "sf1")
    cp = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
    assert cp["kind"] == "checkpoint" and cp["signer_error"] == "SignerError"
    assert "signature" not in cp and "signer" not in cp

    rep = verify_session(log)
    assert not rep.valid and rep.signer_failures == 1
    assert any(e.startswith("ERR_UNSIGNED at seq 2") and "signer failed" in e for e in rep.errors)
    lenient = verify_session(log, require_signed=False)
    assert lenient.valid and lenient.signer_failures == 1
    assert any("signer failed" in w for w in lenient.warnings)
    # The mark is inside the hashed body: removing it breaks the receipt.
    lines = log.read_text(encoding="utf-8").splitlines()
    del cp["signer_error"]
    log.write_text("\n".join([*lines[:-1], json.dumps(cp, sort_keys=True, separators=(",", ":"))]) + "\n",
                   encoding="utf-8")
    assert any(e.startswith("ERR_RECEIPT_HASH") for e in verify_session(log, require_signed=False).errors)

    assert [e["component"] for e in read_errors(session_id="sf1")] == ["signer"]
    r = CliRunner().invoke(cli, ["session", "verify", str(log), "--allow-unsigned"])
    assert "RECORD ERRORS 1 recording failure(s)" in r.output


def test_signer_that_fails_while_signing_still_writes_the_checkpoint(home, tmp_path, capsys):
    from perathos.keytrust import KmsSigner
    from perathos.signers import SignerError

    def refuse(_payload):
        raise SignerError("vault: 503")
    _tool_call(tmp_path, "sf2")
    signer = KmsSigner(key_id="vault:transit/k", public_key=bytes(32), sign_fn=refuse)
    cp = record_hook_event({"hook_event_name": "Stop", "session_id": "sf2", "cwd": str(tmp_path)},
                           signing_key_hex=signer)
    assert cp["signer_error"] == "SignerError" and "signature" not in cp and "signer" not in cp
    assert "sealed UNSIGNED" in capsys.readouterr().err
    log = session_log_path(tmp_path, "sf2")
    rep = verify_session(log)
    assert rep.signer_failures == 1 and not rep.valid
    assert not any(e.startswith(("ERR_RECEIPT_HASH", "ERR_CHAIN")) for e in rep.errors)
    r = CliRunner().invoke(cli, ["session", "verify", str(log)])
    assert r.exit_code == 1 and "SIGNER FAILED 1 checkpoint(s)" in r.output
    # A later checkpoint with a working signer seals the log, but the unsigned one still fails.
    sk, _ = generate_keypair()
    record_hook_event({"hook_event_name": "Stop", "session_id": "sf2", "cwd": str(tmp_path)}, signing_key_hex=sk)
    rep = verify_session(log)
    assert rep.signed_checkpoints == 1 and rep.signer_failures == 1 and not rep.valid


def test_a_failing_signer_only_downgrades_checkpoints(tmp_path):
    with pytest.raises(ValueError):
        append_receipt(session_log_path(tmp_path, "x"), {"session_id": "x", "agent": "t", "kind": "pre"},
                       signing_key_hex="zz")


def test_missing_local_key_is_not_a_signer_failure(home, tmp_path):
    _tool_call(tmp_path, "nk")
    run_record(json.dumps({"hook_event_name": "Stop", "session_id": "nk", "cwd": str(tmp_path)}),
               guard=False, anchor=False, out=io.StringIO(), err=io.StringIO())
    cp = json.loads(session_log_path(tmp_path, "nk").read_text(encoding="utf-8").splitlines()[-1])
    assert "signer_error" not in cp and "signature" not in cp
    assert read_errors() == []


def test_cursor_and_mcp_proxy_mark_signer_failure(home, tmp_path, monkeypatch):
    from perathos.cli import _recorder_signer_strict
    from perathos.integrations.cursor import run_hook
    from perathos.signers import SignerError

    with pytest.raises(FileNotFoundError):  # local signer, no key yet: unsigned, not a failure
        _recorder_signer_strict()
    monkeypatch.setenv("PERATHOS_SIGNER", "command:definitely-not-a-real-signer-binary")
    with pytest.raises(SignerError):
        _recorder_signer_strict()

    warned = []
    base = {"conversation_id": "cs1", "workspace_roots": [str(tmp_path)]}
    run_hook(json.dumps({**base, "hook_event_name": "beforeShellExecution", "command": "ls", "generation_id": "g"}))
    run_hook(json.dumps({**base, "hook_event_name": "stop"}), load_signing_key=_recorder_signer_strict,
             warn=warned.append)
    cp = json.loads(session_log_path(tmp_path, "cs1").read_text(encoding="utf-8").splitlines()[-1])
    assert cp["kind"] == "checkpoint" and cp["signer_error"] == "SignerError"
    assert any("UNSIGNED" in w for w in warned)

    rec = McpRecorder(name="db", project=tmp_path, session_id="ms1", signer_error="SignerError")
    rec.on_tools_call(_call(1))
    assert rec.seal("end")["signer_error"] == "SignerError"
    assert verify_session(rec.log).signer_failures == 1


# --------------------------------------------------------------------------- #
# 4. Recording failures are logged and counted
# --------------------------------------------------------------------------- #

def test_failed_recording_is_logged_and_never_blocks(home, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise TimeoutError("could not lock the session log")
    monkeypatch.setattr("perathos.recorder.record_hook_event", boom)
    out, err = io.StringIO(), io.StringIO()
    payload = {"hook_event_name": "PreToolUse", "session_id": "r1", "cwd": str(tmp_path), "tool_name": "Bash",
               "tool_use_id": "t1", "tool_input": {"command": "ls"}}
    run_record(json.dumps(payload), guard=False, anchor=False, out=out, err=err)
    assert out.getvalue() == ""  # the call is not blocked
    assert "TimeoutError" in err.getvalue()
    entries = read_errors(session_id="r1")
    assert len(entries) == 1
    assert entries[0]["component"] == "claude-code.record" and entries[0]["error"] == "TimeoutError"
    assert entries[0]["ts"].endswith("Z") and entries[0]["project"] == str(tmp_path.resolve())
    assert read_errors(project=tmp_path) == entries and read_errors(session_id="other") == []


def test_cursor_recording_failure_is_logged(home, tmp_path, monkeypatch):
    from perathos.integrations import cursor
    monkeypatch.setattr(cursor, "record_cursor_event", lambda *a, **k: (_ for _ in ()).throw(OSError("read-only")))
    resp = cursor.run_hook(json.dumps({"hook_event_name": "beforeShellExecution", "conversation_id": "c9",
                                       "workspace_roots": [str(tmp_path)], "command": "ls"}))
    assert resp["permission"] == "allow"
    assert [(e["component"], e["error"]) for e in read_errors(session_id="c9")] == [("cursor.record", "OSError")]


def test_error_log_never_raises_and_rolls_over(tmp_path, monkeypatch):
    monkeypatch.setenv("PERATHOS_ERROR_LOG", str(tmp_path / "is-a-dir"))
    (tmp_path / "is-a-dir").mkdir()
    log_error("x", ValueError("y"))  # cannot be written: swallowed
    assert read_errors() == []
    path = tmp_path / "errors.log"
    monkeypatch.setenv("PERATHOS_ERROR_LOG", str(path))
    path.write_text("x" * ((1 << 20) + 1) + "\n", encoding="utf-8")
    log_error("x", "plain message")
    assert errors_log_path() == path and path.with_name("errors.log.1").exists()
    assert [e["error"] for e in read_errors()] == ["plain message"]


def test_doctor_reports_logged_recording_failures(home, tmp_path):
    from perathos.readiness import PASS, WARN, run_checks

    def check():
        return next(c for c in run_checks(tmp_path) if c.check == "recording failures logged")
    assert check().status == PASS
    log_error("claude-code.record", TimeoutError("lock"), session_id="s", project=tmp_path)
    log_error("signer", "SignerError", session_id="t", project=tmp_path / "elsewhere")
    c = check()
    assert c.status == WARN and c.detail.startswith("2 in ") and "(1 for this project)" in c.detail
    assert "signer: SignerError" in c.detail


def test_session_verify_json_carries_the_error_count(home, tmp_path):
    sk, _ = generate_keypair()
    _tool_call(tmp_path, "j1")
    record_hook_event({"hook_event_name": "Stop", "session_id": "j1", "cwd": str(tmp_path)}, signing_key_hex=sk)
    log = session_log_path(tmp_path, "j1")
    r = CliRunner().invoke(cli, ["session", "verify", str(log), "--json"])
    data = json.loads(r.output)
    assert data["recording_errors_logged"] == 0 and data["signer_failures"] == 0
    assert "RECORD ERRORS" not in CliRunner().invoke(cli, ["session", "verify", str(log)]).output


# --------------------------------------------------------------------------- #
# 5. Help text that used to be wrong
# --------------------------------------------------------------------------- #

def test_hooks_install_help_says_the_guard_blocks():
    out = CliRunner().invoke(cli, ["hooks", "install", "--help"]).output
    assert "Neither hook ever blocks the agent" not in out
    assert "Without --guard, neither hook ever blocks the agent" in " ".join(out.split())
    assert "fails closed" in " ".join(out.split())
