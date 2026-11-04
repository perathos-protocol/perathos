"""Flight recorder: chained tool-call receipts, signed checkpoints, tamper detection."""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.cli import cli
from perathos.recorder import (
    GENESIS_HASH,
    head_path_for,
    receipt_hash,
    record_hook_event,
    session_log_path,
    verify_session,
)
from perathos.signing import generate_keypair, sign_hash

SID = "sess-1234"


def _payload(event, tmp_path, **extra):
    return {"hook_event_name": event, "session_id": SID, "cwd": str(tmp_path), **extra}


def _run_session(tmp_path, sk, *, calls=3, seal=True):
    """Simulate a Claude Code turn: N tool calls, then a Stop checkpoint."""
    for i in range(calls):
        tool_input = {"command": f"echo {i}"}
        record_hook_event(_payload("PreToolUse", tmp_path, tool_name="Bash",
                                   tool_use_id=f"t{i}", tool_input=tool_input))
        record_hook_event(_payload("PostToolUse", tmp_path, tool_name="Bash", tool_use_id=f"t{i}",
                                   tool_input=tool_input, tool_response={"stdout": str(i)}))
    if seal:
        record_hook_event(_payload("Stop", tmp_path), signing_key_hex=sk)
    return session_log_path(tmp_path, SID)


def _lines(log: Path) -> list[dict]:
    return [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines() if x.strip()]


def _write(log: Path, recs: list[dict]) -> None:
    log.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")


@pytest.fixture
def keys():
    return generate_keypair()


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Redirect ~/.perathos (signing keys) into the test's temp dir."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


# ── Happy path ───────────────────────────────────────────────────────────────

def test_session_verifies(tmp_path, keys):
    sk, vk = keys
    log = _run_session(tmp_path, sk)
    r = verify_session(log, expected_verify_key=vk)
    assert r.valid, r.errors
    assert (r.receipts, r.tool_calls, r.checkpoints, r.signed_checkpoints) == (7, 3, 1, 1)
    assert r.sealed_through == 7 and r.unsealed_tail == 0
    assert r.signers == [vk]
    assert r.tools == {"Bash": 3}


def test_chain_structure(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    assert recs[0]["prev_hash"] == GENESIS_HASH
    assert [r["seq"] for r in recs] == list(range(1, 8))
    for a, b in zip(recs, recs[1:]):
        assert b["prev_hash"] == a["receipt_hash"]
    assert all(receipt_hash(r) == r["receipt_hash"] for r in recs)


def test_content_is_never_stored(tmp_path, keys):
    secret = "AKIA-SUPER-SECRET-TOKEN-value"
    record_hook_event(_payload("PreToolUse", tmp_path, tool_name="Bash", tool_use_id="x",
                               tool_input={"command": f"export KEY={secret}"}))
    record_hook_event(_payload("PostToolUse", tmp_path, tool_name="Bash", tool_use_id="x",
                               tool_input={}, tool_response=secret))
    assert secret not in session_log_path(tmp_path, SID).read_text(encoding="utf-8")


def test_multiple_turns_each_sealed(tmp_path, keys):
    sk, vk = keys
    _run_session(tmp_path, sk, calls=2)
    log = _run_session(tmp_path, sk, calls=1)
    r = verify_session(log, expected_verify_key=vk)
    assert r.valid, r.errors
    assert r.checkpoints == 2 and r.sealed_through == r.receipts


def test_unsealed_tail_is_a_warning_not_an_error(tmp_path, keys):
    sk, _ = keys
    _run_session(tmp_path, sk, calls=1)
    log = _run_session(tmp_path, sk, calls=2, seal=False)
    r = verify_session(log)
    assert r.valid, r.errors
    assert r.unsealed_tail == 4
    assert any("not sealed" in w for w in r.warnings)


# ── Tampering ────────────────────────────────────────────────────────────────

def test_edited_receipt_detected(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    recs[2]["tool"] = "Read"
    _write(log, recs)
    r = verify_session(log)
    assert not r.valid and any("ERR_RECEIPT_HASH" in e for e in r.errors)


def test_edited_and_rehashed_receipt_breaks_chain(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    recs[2]["result_hash"] = "f" * 64
    recs[2]["receipt_hash"] = receipt_hash(recs[2])
    _write(log, recs)
    r = verify_session(log)
    assert not r.valid and any("ERR_CHAIN" in e for e in r.errors)


def test_deleted_receipt_detected(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    del recs[3]
    _write(log, recs)
    r = verify_session(log)
    assert not r.valid
    assert any("ERR_SEQ" in e for e in r.errors) and any("ERR_CHAIN" in e for e in r.errors)


def test_reordered_receipts_detected(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    recs[1], recs[2] = recs[2], recs[1]
    _write(log, recs)
    assert not verify_session(log).valid


def test_inserted_forged_receipt_detected(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    forged = dict(recs[1], tool="Write", seq=3, prev_hash=recs[1]["receipt_hash"])
    forged["receipt_hash"] = receipt_hash(forged)
    recs.insert(2, forged)
    _write(log, recs)
    r = verify_session(log)
    assert not r.valid and any("ERR_SEQ" in e or "ERR_CHAIN" in e for e in r.errors)


def test_truncation_detected_by_head_witness(tmp_path, keys):
    sk, _ = keys
    _run_session(tmp_path, sk, calls=1)
    log = _run_session(tmp_path, sk, calls=2)  # second checkpoint is the head
    recs = _lines(log)
    first_cp = next(i for i, r in enumerate(recs) if r["kind"] == "checkpoint")
    _write(log, recs[: first_cp + 1])  # cut everything after the first checkpoint
    r = verify_session(log)
    assert not r.valid and any("ERR_TRUNCATED" in e for e in r.errors)


def test_truncation_without_witness_is_a_documented_limit(tmp_path, keys):
    """Without the head witness (or an external anchor) a cut back to an
    earlier checkpoint verifies. This test pins the limit so it is never
    silently over-claimed; external timestamping closes it."""
    sk, _ = keys
    _run_session(tmp_path, sk, calls=1)
    log = _run_session(tmp_path, sk, calls=2)
    recs = _lines(log)
    first_cp = next(i for i, r in enumerate(recs) if r["kind"] == "checkpoint")
    _write(log, recs[: first_cp + 1])
    head_path_for(log).unlink()
    assert verify_session(log).valid


def test_stripped_signature_detected(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    del recs[-1]["signature"]
    _write(log, recs)
    r = verify_session(log, check_head=False)
    assert not r.valid and any("ERR_UNSIGNED" in e for e in r.errors)
    assert verify_session(log, require_signed=False, check_head=False).valid


def test_resigned_by_other_key_caught_by_signer_binding(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    recs = _lines(log)
    other_sk, _ = generate_keypair()
    recs[-1]["signature"] = sign_hash(recs[-1]["receipt_hash"], other_sk)
    _write(log, recs)
    r = verify_session(log, check_head=False)
    assert not r.valid and any("ERR_SIGNER_MISMATCH" in e for e in r.errors)


def test_full_rewrite_with_attacker_key_caught_by_pinning(tmp_path, keys):
    """An attacker who rebuilds the whole log with their own key produces a
    self-consistent log; only pinning the expected signer catches it."""
    sk, vk = keys
    attacker_sk, _ = generate_keypair()
    log = _run_session(tmp_path, attacker_sk)
    assert verify_session(log).valid
    r = verify_session(log, expected_verify_key=vk)
    assert not r.valid and any("ERR_UNEXPECTED_SIGNER" in e for e in r.errors)


def test_unsigned_session_fails_by_default(tmp_path):
    log = _run_session(tmp_path, None)
    r = verify_session(log)
    assert not r.valid and any("ERR_UNSIGNED" in e for e in r.errors)
    assert verify_session(log, require_signed=False).valid


def test_garbage_line_detected(tmp_path, keys):
    log = _run_session(tmp_path, keys[0])
    text = log.read_text(encoding="utf-8").splitlines()
    text.insert(2, "not json at all")
    log.write_text("\n".join(text) + "\n", encoding="utf-8")
    r = verify_session(log)
    assert not r.valid and any("ERR_MALFORMED" in e for e in r.errors)


# ── Concurrency ─────────────────────────────────────────────────────────────

def test_parallel_hooks_keep_one_chain(tmp_path, keys):
    """Claude Code can run tool calls in parallel; the lock must keep a single chain."""
    def worker(i):
        record_hook_event(_payload("PreToolUse", tmp_path, tool_name="Read", tool_use_id=f"p{i}",
                                   tool_input={"file_path": f"/f{i}"}))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    record_hook_event(_payload("Stop", tmp_path), signing_key_hex=keys[0])
    r = verify_session(session_log_path(tmp_path, SID))
    assert r.valid, r.errors
    assert r.tool_calls == 25


# ── CLI ─────────────────────────────────────────────────────────────────────

def test_hooks_record_cli_is_silent_and_never_fails(tmp_path, home):
    runner = CliRunner()
    pre = json.dumps(_payload("PreToolUse", tmp_path, tool_name="Bash", tool_use_id="c1",
                              tool_input={"command": "ls"}))
    r = runner.invoke(cli, ["hooks", "record"], input=pre)
    assert r.exit_code == 0 and r.stdout == ""
    assert session_log_path(tmp_path, SID).exists()
    for bad in ("not json", "[]", ""):
        assert runner.invoke(cli, ["hooks", "record"], input=bad).exit_code == 0


def test_session_verify_cli(tmp_path, home, monkeypatch):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    vk = (home / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    for event, extra in (
        ("PreToolUse", {"tool_name": "Bash", "tool_use_id": "c1", "tool_input": {"command": "ls"}}),
        ("PostToolUse", {"tool_name": "Bash", "tool_use_id": "c1", "tool_input": {"command": "ls"},
                         "tool_response": "a b"}),
        ("Stop", {}),
    ):
        assert runner.invoke(cli, ["hooks", "record"], input=json.dumps(_payload(event, tmp_path, **extra))).exit_code == 0

    monkeypatch.chdir(tmp_path)
    ok = runner.invoke(cli, ["session", "verify", SID, "--verify-key", vk])
    assert ok.exit_code == 0, ok.output
    assert "VALID" in ok.output and "1 tool calls" in ok.output

    wrong = runner.invoke(cli, ["session", "verify", SID, "--verify-key", "f" * 64])
    assert wrong.exit_code == 1

    log = session_log_path(tmp_path, SID)
    recs = _lines(log)
    recs[0]["tool"] = "Write"
    _write(log, recs)
    bad = runner.invoke(cli, ["session", "verify", SID])
    assert bad.exit_code == 1 and "ERR_RECEIPT_HASH" in bad.output

    shown = runner.invoke(cli, ["session", "show", SID])
    assert shown.exit_code == 0 and "SEAL" in shown.output

    assert runner.invoke(cli, ["session", "verify", "no-such-session"]).exit_code == 2
