"""Perathos Gate client side: guard asks a person, waits or retries, verifies the
passkey-signed receipt offline, and binds it into the record. Uses an in-process
stub Gate server with a software passkey (ES256), so no network is needed."""
from __future__ import annotations

import hashlib
import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from perathos.cli import cli
from perathos.gate import (
    GateClient,
    apply_gate,
    b64url,
    build_receipt,
    build_request,
    chash,
    decision_challenge,
    require_approval,
    ApprovalDenied,
    verify_receipt,
)
from perathos.guard import Decision
from perathos.recorder import session_log_path
from perathos.signing import generate_keypair

RP = {"id": "localhost", "origin": "http://localhost:8787"}


class StubGate:
    """Minimal Gate server implementing the spec's agent-side API."""

    def __init__(self, server_sk=None):
        self.server_sk, self.server_vk = generate_keypair()
        if server_sk is not None:
            self.server_sk = server_sk
        self.approvals: dict[str, dict] = {}
        self.passkey = ec.generate_private_key(ec.SECP256R1())
        self.pub = self.passkey.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo)
        self.created = 0
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                u = urlparse(self.path)
                if u.path == "/.well-known/perathos-gate.json":
                    return self._send(200, {"gate": "gate_test", "verify_key": stub.server_vk, "rp_id": RP["id"],
                                            "origin": RP["origin"], "version": 1})
                if self.headers.get("Authorization") != "Bearer key-1":
                    return self._send(401, {"error": "unauthorized"})
                aid = u.path.rsplit("/", 1)[-1]
                wait = int(parse_qs(u.query).get("wait", ["0"])[0])
                deadline = time.monotonic() + min(wait, 60)
                while stub.approvals[aid]["status"] == "pending" and time.monotonic() < deadline:
                    time.sleep(0.05)
                a = stub.approvals[aid]
                return self._send(200, {"id": aid, "status": a["status"], "receipt": a.get("receipt")})

            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer key-1":
                    return self._send(401, {"error": "unauthorized"})
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                req = build_request(org="org_1", gate="gate_test", action=body["action"], agent=body["agent"],
                                    args_hash=body["args_hash"], ttl_seconds=body.get("ttl_seconds", 600))
                stub.approvals[req["id"]] = {"status": "pending", "request": req}
                stub.created += 1
                return self._send(201, {"id": req["id"], "status": "pending", "request": req,
                                        "approve_url": f"{RP['origin']}/a/{req['id']}?t=x", "expires_at": req["expires_at"]})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def decide(self, aid: str, decision: str, *, user_verified=True):
        a = self.approvals[aid]
        rh = chash(a["request"])
        cd = json.dumps({"type": "webauthn.get", "challenge": b64url(decision_challenge(rh, decision)),
                         "origin": RP["origin"]}).encode()
        ad = hashlib.sha256(RP["id"].encode()).digest() + bytes([0x05 if user_verified else 0x01]) + (7).to_bytes(4, "big")
        sig = self.passkey.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        a["receipt"] = build_receipt(
            request=a["request"], decision=decision,
            approver={"name": "Alice Moyo", "credential_id": "Y3JlZC0x", "public_key": b64url(self.pub), "alg": -7,
                      "enrolled_at": "2026-11-01T00:00:00Z"},
            rp=RP, webauthn={"authenticator_data": b64url(ad), "client_data_json": b64url(cd), "signature": b64url(sig)},
            server_signer=self.server_sk)
        a["status"] = "approved" if decision == "approve" else "denied"

    def only_pending(self) -> str:
        return next(k for k, v in self.approvals.items() if v["status"] == "pending")

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def gate(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    for v in ("PERATHOS_GATE_URL", "PERATHOS_GATE_API_KEY", "PERATHOS_GATE_KEY", "PERATHOS_SIGNER"):
        monkeypatch.delenv(v, raising=False)
    g = StubGate()
    yield g
    g.close()


def _login(g, wait=5):
    r = CliRunner().invoke(cli, ["gate", "login", "--url", g.url, "--api-key", "key-1", "--wait", str(wait)])
    assert r.exit_code == 0, r.output


DENY = Decision("deny", "db.dropdb", None, "perathos guard: blocked PostgreSQL dropdb (db.dropdb). No precondition.")
ARGS = {"command": "dropdb prod"}


def test_login_pins_the_gate_key(gate):
    _login(gate)
    c = GateClient.from_config()
    assert c.gate_key == gate.server_vk
    assert CliRunner().invoke(cli, ["gate", "status"]).exit_code == 0


def test_pending_then_retry_after_approval(gate, tmp_path):
    _login(gate)
    d1 = apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    assert d1.decision == "deny" and "Approval requested" in d1.reason and "/a/apr_" in d1.reason
    d2 = apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    assert d2.decision == "deny" and gate.created == 1  # same request reused, no spam
    gate.decide(gate.only_pending(), "approve")
    d3 = apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    assert d3.decision == "allow" and d3.approval and d3.receipt_field()["approval"] == d3.approval
    # single use: the next identical command needs a new approval
    d4 = apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    assert d4.decision == "deny" and gate.created == 2


def test_approval_for_other_arguments_is_not_used(gate, tmp_path):
    _login(gate)
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    gate.decide(gate.only_pending(), "approve")
    d = apply_gate(DENY, tool="Bash", args={"command": "dropdb customers"}, cwd=tmp_path, wait_seconds=0)
    assert d.decision == "deny"


def test_claude_code_hook_waits_for_phone_approval(gate, tmp_path):
    from perathos.hook import run_record
    _login(gate, wait=10)

    def approve_soon():
        for _ in range(100):
            if any(a["status"] == "pending" for a in gate.approvals.values()):
                gate.decide(gate.only_pending(), "approve")
                return
            time.sleep(0.05)
    threading.Thread(target=approve_soon, daemon=True).start()
    out = io.StringIO()
    payload = {"hook_event_name": "PreToolUse", "session_id": "g1", "cwd": str(tmp_path), "tool_name": "Bash",
               "tool_use_id": "t1", "tool_input": ARGS}
    run_record(json.dumps(payload), guard=True, anchor=False, out=out, err=io.StringIO())
    assert out.getvalue() == ""  # allowed: no deny emitted
    rec = json.loads(session_log_path(tmp_path, "g1").read_text(encoding="utf-8").splitlines()[0])
    assert rec["guard"]["decision"] == "allow" and len(rec["guard"]["approval"]) == 64
    saved = list((tmp_path / ".perathos" / "approvals").glob("apr_*.json"))
    assert len(saved) == 1 and saved[0].with_suffix(".used").exists()


def test_denial_is_reported_with_the_approver(gate, tmp_path):
    _login(gate)
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    gate.decide(gate.only_pending(), "deny")
    d = apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    assert d.decision == "deny" and "Alice Moyo denied" in d.reason


def test_receipt_from_an_unpinned_server_key_is_rejected(gate, tmp_path):
    _login(gate)
    other_sk, _ = generate_keypair()
    gate.server_sk = other_sk  # server now signs with a key the client did not pin
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    gate.decide(gate.only_pending(), "approve")
    d = apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    assert d.decision == "deny" and "ERR_GATE_UNEXPECTED_SERVER" in d.reason


def test_no_user_verification_is_rejected(gate, tmp_path):
    _login(gate)
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    gate.decide(gate.only_pending(), "approve", user_verified=False)
    d = apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    assert d.decision == "deny" and "USER_VERIFICATION" in d.reason


def test_self_authorization_is_never_sent_for_approval(gate, tmp_path):
    _login(gate)
    d = apply_gate(Decision("deny", "guard.self-authorize", None, "blocked"), tool="Bash", args={"command": "perathos keygen"},
                   cwd=tmp_path, wait_seconds=0)
    assert d.decision == "deny" and gate.created == 0


def test_without_gate_config_nothing_changes(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0) is DENY


def test_sdk_require_approval(gate):
    _login(gate)

    def decide_soon(decision):
        for _ in range(100):
            if any(a["status"] == "pending" for a in gate.approvals.values()):
                gate.decide(gate.only_pending(), decision)
                return
            time.sleep(0.05)
    threading.Thread(target=decide_soon, args=("approve",), daemon=True).start()
    receipt = require_approval("Wire $5,000 to ACME Ltd", tool="payments.transfer",
                               args={"to": "ACME", "amount": 5000}, wait_seconds=10)
    assert verify_receipt(receipt, gate_key=gate.server_vk)
    threading.Thread(target=decide_soon, args=("deny",), daemon=True).start()
    with pytest.raises(ApprovalDenied, match="Alice Moyo"):
        require_approval("Wire $9,000 to ACME Ltd", wait_seconds=10)


def test_cli_request_and_verify(gate, tmp_path):
    _login(gate)
    runner = CliRunner()

    def approve_soon():
        for _ in range(100):
            if any(a["status"] == "pending" for a in gate.approvals.values()):
                gate.decide(gate.only_pending(), "approve")
                return
            time.sleep(0.05)
    threading.Thread(target=approve_soon, daemon=True).start()
    out = tmp_path / "r.json"
    r = runner.invoke(cli, ["gate", "request", "--summary", "drop table orders", "--wait", "10", "--out", str(out)])
    assert r.exit_code == 0, r.output
    v = runner.invoke(cli, ["gate", "verify", str(out)])
    assert v.exit_code == 0 and v.output.startswith("VALID  APPROVE by Alice Moyo")
    data = json.loads(out.read_text(encoding="utf-8"))
    data["request"]["action"]["summary"] = "something else"
    out.write_text(json.dumps(data), encoding="utf-8")
    assert runner.invoke(cli, ["gate", "verify", str(out)]).exit_code == 1
    # no decision in time -> exit 3
    assert runner.invoke(cli, ["gate", "request", "--summary", "x", "--wait", "1"]).exit_code == 3


def test_evidence_pack_carries_and_checks_approvals(gate, tmp_path):
    from perathos.evidence import export_evidence_pack, verify_evidence_pack
    from perathos.hook import run_record
    _login(gate)
    sk, vk = generate_keypair()
    payload = {"hook_event_name": "PreToolUse", "session_id": "e1", "cwd": str(tmp_path), "tool_name": "Bash",
               "tool_use_id": "t1", "tool_input": ARGS}
    apply_gate(DENY, tool="Bash", args=ARGS, cwd=tmp_path, wait_seconds=0)
    gate.decide(gate.only_pending(), "approve")
    run_record(json.dumps(payload), guard=True, anchor=False, out=io.StringIO(), err=io.StringIO())
    from perathos.recorder import record_hook_event
    record_hook_event({"hook_event_name": "Stop", "session_id": "e1", "cwd": str(tmp_path)}, signing_key_hex=sk)
    res = export_evidence_pack(session_log_path(tmp_path, "e1"), tmp_path / "pack", signing_key_hex=sk)
    rep = res["report"]
    assert rep["approved_by_person"] and rep["approved_by_person"][0]["approver"] == "Alice Moyo"
    assert verify_evidence_pack(res["dir"], expected_verify_key=vk)["valid"]
    f = next((res["dir"] / "approvals").glob("*.json"))
    data = json.loads(f.read_text(encoding="utf-8"))
    data["decision"] = "deny"
    f.write_text(json.dumps(data), encoding="utf-8")
    errs = verify_evidence_pack(res["dir"], expected_verify_key=vk)["errors"]
    assert any("ERR_GATE_RECEIPT_HASH" in e for e in errs)


@pytest.mark.exec_hooks
def test_installer_gives_the_guard_time_to_wait(gate, tmp_path, monkeypatch):
    _login(gate, wait=120)
    monkeypatch.chdir(tmp_path)
    assert CliRunner().invoke(cli, ["hooks", "install", "--guard"]).exit_code == 0
    pre = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]["hooks"][0]
    assert pre["timeout"] == 150 and pre["onFailure"] == "block"
