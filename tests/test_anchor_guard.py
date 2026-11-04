"""Week 3: RFC 3161 anchors on checkpoints, and the destructive-command guard."""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos import anchor as anchor_mod
from perathos.anchor import ANCHOR_VERSION, load_roots, verify_timestamp
from perathos.cli import cli
from perathos.guard import (
    check_precondition,
    create_precondition,
    decide,
    evaluate,
    preconditions_dir,
)
from perathos.recorder import record_hook_event, session_log_path, verify_session
from perathos.signing import generate_keypair

FIXTURES = Path(__file__).parent / "fixtures"
TOKEN = (FIXTURES / "freetsa_token_ab.tsr").read_bytes()
TOKEN_HASH = "ab" * 32  # the receipt hash the fixture token was issued for
SID = "sess-w3"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def _payload(event, cwd, **extra):
    return {"hook_event_name": event, "session_id": SID, "cwd": str(cwd), **extra}


def _sealed_session(cwd, sk, calls=2):
    for i in range(calls):
        record_hook_event(_payload("PreToolUse", cwd, tool_name="Bash", tool_use_id=f"t{i}",
                                   tool_input={"command": f"echo {i}"}))
        record_hook_event(_payload("PostToolUse", cwd, tool_name="Bash", tool_use_id=f"t{i}",
                                   tool_input={"command": f"echo {i}"}, tool_response=str(i)))
    return record_hook_event(_payload("Stop", cwd), signing_key_hex=sk)


# ── RFC 3161 token verification (offline, real FreeTSA token) ────────────────

def test_real_token_verifies_against_pinned_root():
    ok, gen = verify_timestamp(TOKEN, TOKEN_HASH, load_roots())
    assert ok and gen.startswith("2026-")


def test_token_for_other_hash_rejected():
    assert verify_timestamp(TOKEN, "cd" * 32, load_roots()) == (False, "ERR_ANCHOR_MISMATCH")


def test_token_rejected_without_its_root():
    """Embedded certificates must never be trusted on their own."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated Root")])
    now = dt.datetime.now(dt.timezone.utc)
    unrelated = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                 .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                 .sign(key, hashes.SHA256()))
    ok, err = verify_timestamp(TOKEN, TOKEN_HASH, [unrelated])
    assert not ok and err == "ERR_ANCHOR_UNTRUSTED"


def test_garbage_token_rejected():
    assert verify_timestamp(b"not a token", TOKEN_HASH, load_roots()) == (False, "ERR_ANCHOR_MALFORMED")


# ── Anchors cross-checked against the log ────────────────────────────────────

def _anchor_line(seq, receipt_hash, token=TOKEN):
    return json.dumps({"v": ANCHOR_VERSION, "session_id": SID, "seq": seq, "receipt_hash": receipt_hash,
                       "tsa": "test", "gen_time": "x", "token": base64.b64encode(token).decode()}) + "\n"


def test_anchor_beyond_log_proves_truncation(tmp_path):
    """An outside timestamp for a checkpoint the log no longer has = the log was cut."""
    sk, _ = generate_keypair()
    cp = _sealed_session(tmp_path, sk)
    anchors = tmp_path / "anchors.jsonl"
    anchors.write_text(_anchor_line(cp["seq"] + 5, TOKEN_HASH), encoding="utf-8")
    r = verify_session(session_log_path(tmp_path, SID), anchors_path=anchors)
    assert not r.valid and any("ERR_TRUNCATED" in e for e in r.errors)


def test_anchor_for_different_hash_rejected(tmp_path):
    sk, _ = generate_keypair()
    cp = _sealed_session(tmp_path, sk)
    anchors = tmp_path / "anchors.jsonl"
    anchors.write_text(_anchor_line(cp["seq"], TOKEN_HASH), encoding="utf-8")  # token is for another hash
    r = verify_session(session_log_path(tmp_path, SID), anchors_path=anchors)
    assert not r.valid and any("ERR_ANCHOR_MISMATCH" in e for e in r.errors)


def test_matching_anchor_accepted_and_require_anchor(tmp_path, monkeypatch):
    sk, _ = generate_keypair()
    cp = _sealed_session(tmp_path, sk)
    log = session_log_path(tmp_path, SID)
    anchors = tmp_path / "anchors.jsonl"
    anchors.write_text(_anchor_line(cp["seq"], cp["receipt_hash"]), encoding="utf-8")
    # The fixture token was issued for TOKEN_HASH; stand in for the TSA check here.
    monkeypatch.setattr(anchor_mod, "verify_timestamp",
                        lambda tok, h, roots: (True, "2099-01-01T00:00:00Z") if h == cp["receipt_hash"] else (False, "x"))
    r = verify_session(log, anchors_path=anchors, require_anchor=True)
    assert r.valid, r.errors
    assert r.anchors == 1 and r.anchored_through == cp["seq"]

    # a new, un-anchored turn fails --require-anchor
    _sealed_session(tmp_path, sk, calls=1)
    r = verify_session(log, anchors_path=anchors, require_anchor=True)
    assert not r.valid and any("ERR_NOT_ANCHORED" in e for e in r.errors)


def test_require_anchor_without_anchors_fails(tmp_path):
    sk, _ = generate_keypair()
    _sealed_session(tmp_path, sk)
    r = verify_session(session_log_path(tmp_path, SID), require_anchor=True)
    assert not r.valid and any("ERR_NOT_ANCHORED" in e for e in r.errors)


@pytest.mark.integration
def test_live_anchor_round_trip(tmp_path):
    """Hits freetsa.org; skipped when offline."""
    sk, _ = generate_keypair()
    cp = _sealed_session(tmp_path, sk)
    anchors = tmp_path / "anchors.jsonl"
    try:
        anchor_mod.anchor_checkpoint(cp, anchors, timeout=10)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"TSA unreachable: {exc}")
    r = verify_session(session_log_path(tmp_path, SID), anchors_path=anchors, require_anchor=True)
    assert r.valid, r.errors


# ── Guard rules ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cmd", [
    "rm -rf ./data",
    "rm -fr /var/lib/postgres",
    "psql -c 'DROP DATABASE prod'",
    "psql -c \"drop table users\"",
    "psql -c 'TRUNCATE orders'",
    "psql -c 'delete from users;'",
    "dropdb prod",
    "redis-cli FLUSHALL",
    "terraform destroy -auto-approve",
    "kubectl delete pvc data-pg-0",
    "aws s3 rm s3://backups --recursive",
    "aws rds delete-db-instance --db-instance-identifier prod",
    "railway volume delete pg-data",
    "railway down",
    "docker volume rm pgdata",
    "npx prisma migrate reset --force",
    "git push --force origin main",
    "Remove-Item -Recurse C:/data",
])
def test_destructive_commands_match(cmd):
    assert evaluate("Bash", {"command": cmd}) is not None, cmd


@pytest.mark.parametrize("cmd", [
    "ls -la",
    "rm notes.txt",
    "git push origin feature/x",
    "psql -c 'delete from users where id = 4'",
    "pytest -q",
    "terraform plan",
    "kubectl get pods",
])
def test_safe_commands_do_not_match(cmd):
    assert evaluate("Bash", {"command": cmd}) is None, cmd


def test_destructive_mcp_tool_matches():
    assert evaluate("mcp__railway__volume_delete", {"volumeId": "v1"}) is not None
    assert evaluate("mcp__railway__list_volumes", {}) is None


def test_agent_cannot_self_authorize(tmp_path):
    _, vk = generate_keypair()
    for cmd in ("perathos precondition add --scope '*' --manual ok", "perathos keygen", "cat ~/.perathos/keys/signing.key"):
        d = decide("Bash", {"command": cmd}, tmp_path, trusted_key=vk)
        assert d is not None and d.decision == "deny", cmd
    d = decide("Read", {"file_path": str(Path.home() / ".perathos" / "keys" / "signing.key")}, tmp_path, trusted_key=vk)
    assert d is not None and d.decision == "deny"


# ── Preconditions ────────────────────────────────────────────────────────────

def _ok_cmd():
    return f'"{sys.executable}" -c "print(42)"'


def _fail_cmd():
    return f'"{sys.executable}" -c "import sys; sys.exit(3)"'


def test_precondition_needs_passing_check(tmp_path):
    sk, vk = generate_keypair()
    pc, res = create_precondition(tmp_path, scope="prod-db", signing_key_hex=sk, check=_fail_cmd())
    assert pc is None and res["exit_code"] == 3
    assert not preconditions_dir(tmp_path).exists() or not list(preconditions_dir(tmp_path).glob("*.json"))

    pc, res = create_precondition(tmp_path, scope="prod-db", signing_key_hex=sk, check=_ok_cmd())
    assert pc is not None and res["exit_code"] == 0
    assert check_precondition(pc, trusted_key=vk) is None


def test_guard_allows_only_with_matching_precondition(tmp_path):
    sk, vk = generate_keypair()
    cmd = {"command": "dropdb prod-db"}
    assert decide("Bash", cmd, tmp_path, trusted_key=vk).decision == "deny"

    create_precondition(tmp_path, scope="staging-db", signing_key_hex=sk, check=_ok_cmd())
    assert decide("Bash", cmd, tmp_path, trusted_key=vk).decision == "deny"  # wrong scope

    pc, _ = create_precondition(tmp_path, scope="prod-db", signing_key_hex=sk, check=_ok_cmd())
    d = decide("Bash", cmd, tmp_path, trusted_key=vk)
    assert d.decision == "allow" and d.precondition == pc["precondition_hash"]


def test_guard_rejects_forged_expired_and_foreign_preconditions(tmp_path):
    sk, vk = generate_keypair()
    other_sk, _ = generate_keypair()
    cmd = {"command": "terraform destroy"}

    pc, _ = create_precondition(tmp_path, scope="*", signing_key_hex=other_sk, manual_reason="x")
    assert decide("Bash", cmd, tmp_path, trusted_key=vk).decision == "deny"  # untrusted signer

    for f in preconditions_dir(tmp_path).glob("*.json"):
        f.unlink()
    pc, _ = create_precondition(tmp_path, scope="*", signing_key_hex=sk, manual_reason="x")
    f = preconditions_dir(tmp_path) / f"{pc['id']}.json"
    data = json.loads(f.read_text(encoding="utf-8"))
    data["expires"] = "2099-01-01T00:00:00Z"  # extend it by hand
    f.write_text(json.dumps(data), encoding="utf-8")
    assert decide("Bash", cmd, tmp_path, trusted_key=vk).decision == "deny"  # modified

    data["expires"] = "2000-01-01T00:00:00Z"
    assert check_precondition(data, trusted_key=vk) is not None


def test_no_key_means_deny(tmp_path):
    assert decide("Bash", {"command": "rm -rf build"}, tmp_path, trusted_key=None).decision == "deny"


# ── Hook end to end ──────────────────────────────────────────────────────────

def test_guard_hook_denies_records_and_then_allows(tmp_path, home, monkeypatch):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    pre = _payload("PreToolUse", tmp_path, tool_name="Bash", tool_use_id="d1",
                   tool_input={"command": "railway volume delete pg-data"})

    r = runner.invoke(cli, ["hooks", "record", "--guard"], input=json.dumps(pre))
    assert r.exit_code == 0
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and "precondition" in out["permissionDecisionReason"]

    # a person adds the precondition (from the project directory)
    monkeypatch.chdir(tmp_path)
    added = runner.invoke(cli, ["precondition", "add", "--scope", "pg-data", "--check", _ok_cmd()])
    assert added.exit_code == 0, added.output

    pre["tool_use_id"] = "d2"
    r = runner.invoke(cli, ["hooks", "record", "--guard"], input=json.dumps(pre))
    assert r.exit_code == 0 and r.stdout == ""  # allowed: nothing printed

    # non-destructive calls are untouched
    safe = _payload("PreToolUse", tmp_path, tool_name="Bash", tool_use_id="s1", tool_input={"command": "ls"})
    r = runner.invoke(cli, ["hooks", "record", "--guard"], input=json.dumps(safe))
    assert r.stdout == ""

    runner.invoke(cli, ["hooks", "record"], input=json.dumps(_payload("Stop", tmp_path)))
    recs = [json.loads(x) for x in session_log_path(tmp_path, SID).read_text(encoding="utf-8").splitlines()]
    guards = [x.get("guard") for x in recs if x["kind"] == "pre"]
    assert guards[0]["decision"] == "deny" and guards[0]["precondition"] is None
    assert guards[1]["decision"] == "allow" and len(guards[1]["precondition"]) == 64
    assert guards[2] is None

    rep = verify_session(session_log_path(tmp_path, SID))
    assert rep.valid, rep.errors
    assert rep.blocked == 1


def test_failed_check_creates_no_precondition_cli(tmp_path, home, monkeypatch):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(cli, ["precondition", "add", "--scope", "x", "--check", _fail_cmd()])
    assert r.exit_code == 1 and "no precondition" in r.output
    assert runner.invoke(cli, ["precondition", "add", "--scope", "x"]).exit_code == 2  # neither check nor manual


def test_install_guard_and_anchor_flags(tmp_path, monkeypatch, home):
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(cli, ["hooks", "install", "--guard", "--anchor"])
    assert r.exit_code == 0, r.output
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    assert hooks["PreToolUse"][0]["hooks"][0]["command"] == "perathos-hook record --guard"
    assert hooks["PostToolUse"][0]["hooks"][0]["command"] == "perathos-hook record"
    stop_cmds = [e["hooks"][0]["command"] for e in hooks["Stop"]]
    assert "perathos-hook record --anchor" in stop_cmds
    assert hooks["SessionEnd"][0]["hooks"][0]["command"] == "perathos-hook record --anchor"


def test_reinstall_with_new_flags_replaces_recorder_entries(tmp_path, monkeypatch, home):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    assert runner.invoke(cli, ["hooks", "install", "--recorder"]).exit_code == 0
    assert runner.invoke(cli, ["hooks", "install", "--guard", "--force"]).exit_code == 0
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    assert [e["hooks"][0]["command"] for e in hooks["PreToolUse"]] == ["perathos-hook record --guard"]


def test_anchor_failure_never_breaks_the_turn(tmp_path, home, monkeypatch):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0

    def boom(*a, **k):
        raise OSError("network down")
    monkeypatch.setattr(anchor_mod, "request_timestamp", boom)
    r = runner.invoke(cli, ["hooks", "record", "--anchor"], input=json.dumps(_payload("Stop", tmp_path)))
    assert r.exit_code == 0 and r.stdout == ""
    assert session_log_path(tmp_path, SID).exists()  # the checkpoint is still written
    assert not os.path.exists(Path(home) / ".perathos" / "anchors" / f"{SID}.jsonl")
