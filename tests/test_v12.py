"""1.2.0: remote signers, approver keys, anchor mirror, exec-form hook installs,
readiness report."""
from __future__ import annotations

import base64
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from perathos.cli import cli
from perathos.guard import create_precondition, decide
from perathos.recorder import record_hook_event, session_log_path, verify_session
from perathos.signers import SignerError, command_signer, gcpkms_signer, signer_from_spec, vault_signer
from perathos.signing import generate_keypair


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.delenv("PERATHOS_SIGNER", raising=False)
    monkeypatch.delenv("PERATHOS_APPROVERS", raising=False)
    monkeypatch.delenv("PERATHOS_ANCHOR_MIRROR", raising=False)
    return tmp_path


# ── command: signer ─────────────────────────────────────────────────────────

SIGNER_SCRIPT = '''
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(sys.argv[1]).read().strip()))
verb = sys.argv[2]
if verb == "pubkey":
    print(sk.public_key().public_bytes_raw().hex())
elif verb == "sign":
    msg = bytes.fromhex(sys.stdin.read().strip())
    sig = sk.sign(msg)
    if len(sys.argv) > 3 and sys.argv[3] == "corrupt":
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    print(sig.hex())
'''


def _command_spec(tmp_path, corrupt=False):
    sk, vk = generate_keypair()
    (tmp_path / "k.hex").write_text(sk, encoding="utf-8")
    (tmp_path / "hsm.py").write_text(SIGNER_SCRIPT, encoding="utf-8")
    script = (tmp_path / "hsm.py").as_posix()
    key = (tmp_path / "k.hex").as_posix()
    # The signer appends the verb (pubkey|sign) to the command; "corrupt" goes after it.
    cmd = f'"{sys.executable}" "{script}" "{key}"'
    return cmd, vk


def test_command_signer_signs_and_seals_a_log(tmp_path):
    cmd, vk = _command_spec(tmp_path)
    s = command_signer(cmd)
    assert s.public_key.hex() == vk
    record_hook_event({"hook_event_name": "PreToolUse", "session_id": "c1", "cwd": str(tmp_path),
                       "tool_name": "Bash", "tool_use_id": "a", "tool_input": {"command": "ls"}})
    record_hook_event({"hook_event_name": "Stop", "session_id": "c1", "cwd": str(tmp_path)}, signing_key_hex=s)
    rep = verify_session(session_log_path(tmp_path, "c1"), expected_verify_key=vk)
    assert rep.valid, rep.errors


def test_command_signer_rejects_bad_signature(tmp_path):
    sk, vk = generate_keypair()
    (tmp_path / "k.hex").write_text(sk, encoding="utf-8")
    bad = tmp_path / "bad.py"
    bad.write_text(SIGNER_SCRIPT.replace('elif verb == "sign":', 'elif verb == "sign":\n    sys.argv.append("corrupt")'),
                   encoding="utf-8")
    s = command_signer(f'"{sys.executable}" "{bad.as_posix()}" "{(tmp_path / "k.hex").as_posix()}"')
    with pytest.raises(SignerError, match="does not verify"):
        s.sign(b"x" * 32)


# ── vault: signer against a local stub of the transit API ───────────────────

def test_vault_signer_against_stub(monkeypatch):
    sk = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            seen["token"] = self.headers.get("X-Vault-Token")
            assert self.path == "/v1/transit/keys/perathos"
            self._send({"data": {"type": "ed25519", "latest_version": 2,
                                 "keys": {"2": {"public_key": pub_b64}}}})

        def do_POST(self):
            assert self.path == "/v1/transit/sign/perathos"
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            sig = sk.sign(base64.b64decode(body["input"]))
            self._send({"data": {"signature": "vault:v2:" + base64.b64encode(sig).decode()}})

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{srv.server_port}")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        s = signer_from_spec("vault:transit/perathos")
        sig = s.sign(b"hello")
        sk.public_key().verify(sig, b"hello")
        assert seen["token"] == "test-token"
    finally:
        srv.shutdown()


def test_vault_signer_needs_env(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(SignerError, match="VAULT_ADDR"):
        vault_signer("transit/perathos")


# ── gcpkms: signer with an injected client ──────────────────────────────────

def test_gcpkms_signer_with_fake_client():
    sk = Ed25519PrivateKey.generate()
    pem = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    class Fake:
        def get_public_key(self, request):
            return type("R", (), {"pem": pem})()

        def asymmetric_sign(self, request):
            return type("R", (), {"signature": sk.sign(request["data"])})()

    s = gcpkms_signer("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", client=Fake())
    sk.public_key().verify(s.sign(b"data"), b"data")
    assert s.public_key == sk.public_key().public_bytes_raw()


def test_unknown_spec():
    with pytest.raises(SignerError, match="unknown signer"):
        signer_from_spec("aws:whatever")


# ── approvers ───────────────────────────────────────────────────────────────

def test_listed_approvers_replace_the_recorder_key(home, tmp_path):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    recorder_sk = (home / ".perathos" / "keys" / "signing.key").read_text(encoding="utf-8").strip()
    approver_sk, approver_vk = generate_keypair()
    project = tmp_path / "proj"
    project.mkdir()
    from perathos.approvers import trusted_approver_keys

    # default: the recorder key approves
    create_precondition(project, scope="*", signing_key_hex=recorder_sk, manual_reason="ok")
    assert decide("Bash", {"command": "dropdb prod"}, project, trusted_key=trusted_approver_keys()).decision == "allow"

    # once an approver is listed, the recorder key's precondition no longer counts
    r = runner.invoke(cli, ["approvers", "add", "--name", "alice", "--key", approver_vk])
    assert r.exit_code == 0, r.output
    assert trusted_approver_keys() == {approver_vk}
    assert decide("Bash", {"command": "dropdb prod"}, project, trusted_key=trusted_approver_keys()).decision == "deny"

    create_precondition(project, scope="*", signing_key_hex=approver_sk, manual_reason="alice checked the snapshot")
    d = decide("Bash", {"command": "dropdb prod"}, project, trusted_key=trusted_approver_keys())
    assert d.decision == "allow"

    listed = runner.invoke(cli, ["approvers", "list"])
    assert "alice" in listed.output
    assert runner.invoke(cli, ["approvers", "remove", "alice"]).exit_code == 0


def test_precondition_add_with_remote_signer_and_warning(home, tmp_path, monkeypatch):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    cmd, vk = _command_spec(tmp_path)
    project = tmp_path / "p2"
    project.mkdir()
    monkeypatch.chdir(project)
    r = runner.invoke(cli, ["precondition", "add", "--scope", "x", "--manual", "y", "--signer", f"command:{cmd}"])
    assert r.exit_code == 0, r.output
    assert "not a trusted approver" in r.output  # warned: key not listed yet
    assert runner.invoke(cli, ["approvers", "add", "--name", "hsm", "--signer", f"command:{cmd}"]).exit_code == 0
    r = runner.invoke(cli, ["precondition", "add", "--scope", "x", "--manual", "y", "--signer", f"command:{cmd}"])
    assert r.exit_code == 0 and "not a trusted approver" not in r.output
    assert "approver      hsm" in r.output


def test_signer_and_config_commands(home):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    ok = runner.invoke(cli, ["signer"])
    assert ok.exit_code == 0 and ok.output.startswith("OK    local")
    assert runner.invoke(cli, ["signer", "vault:transit/x"]).exit_code == 1
    assert runner.invoke(cli, ["config", "anchor_mirror", str(home / "mirror")]).exit_code == 0
    assert str(home / "mirror") in runner.invoke(cli, ["config"]).output
    assert runner.invoke(cli, ["config", "nonsense", "1"]).exit_code == 2
    assert runner.invoke(cli, ["config", "anchor_mirror", "--unset"]).exit_code == 0


def test_hook_uses_configured_remote_signer(home, tmp_path):
    from perathos.approvers import set_config
    from perathos.hook import run_record
    import io
    cmd, vk = _command_spec(tmp_path)
    set_config("signer", f"command:{cmd}")
    payload = {"hook_event_name": "Stop", "session_id": "h1", "cwd": str(tmp_path)}
    run_record(json.dumps(payload), guard=False, anchor=False, out=io.StringIO(), err=io.StringIO())
    rep = verify_session(session_log_path(tmp_path, "h1"), expected_verify_key=vk)
    assert rep.valid, rep.errors


# ── anchor mirror ───────────────────────────────────────────────────────────

def test_anchor_mirror_gets_a_copy(home, tmp_path, monkeypatch):
    from perathos.anchor import append_anchor
    mirror = tmp_path / "share"
    monkeypatch.setenv("PERATHOS_ANCHOR_MIRROR", str(mirror))
    cp = {"session_id": "m1", "seq": 3, "receipt_hash": "ab" * 32}
    main = home / ".perathos" / "anchors" / "m1.jsonl"
    append_anchor(main, cp, b"token", "https://tsa", "2026-11-05T00:00:00Z")
    assert main.read_text(encoding="utf-8") == (mirror / "m1.jsonl").read_text(encoding="utf-8")


# ── exec-form installs and readiness ────────────────────────────────────────

@pytest.mark.exec_hooks
def test_install_writes_exec_form_with_absolute_paths(tmp_path, monkeypatch, home):
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(cli, ["hooks", "install", "--guard", "--anchor"])
    assert r.exit_code == 0, r.output
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    pre = hooks["PreToolUse"][0]["hooks"][0]
    assert Path(pre["command"]).is_file() and Path(pre["command"]).name.lower().startswith("perathos-hook")
    assert pre["args"] == ["record", "--guard"] and pre["onFailure"] == "block"
    stop = [h for e in hooks["Stop"] for h in e["hooks"]]
    assert any(h.get("args") == ["hooks", "stop-check"] for h in stop)
    assert any(h.get("args") == ["record", "--anchor"] for h in stop)
    # reinstall recognises exec-form entries (no duplicates) and old string entries upgrade
    assert CliRunner().invoke(cli, ["hooks", "install", "--guard"]).exit_code == 1
    assert CliRunner().invoke(cli, ["hooks", "install", "--guard", "--force"]).exit_code == 0
    hooks = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]
    assert len(hooks["PreToolUse"]) == 1


@pytest.mark.exec_hooks
def test_readiness_report(tmp_path, monkeypatch, home):
    from perathos.readiness import FAIL, PASS, WARN, run_checks
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen"]).exit_code == 0
    monkeypatch.chdir(tmp_path)
    before = {c.check: c.status for c in run_checks(tmp_path)}
    assert before["recorder hooks"] == FAIL
    assert runner.invoke(cli, ["hooks", "install", "--guard", "--anchor"]).exit_code == 0
    record_hook_event({"hook_event_name": "Stop", "session_id": "r1", "cwd": str(tmp_path)},
                      signing_key_hex=(home / ".perathos" / "keys" / "signing.key").read_text(encoding="utf-8").strip())
    checks = {c.check: c.status for c in run_checks(tmp_path)}
    assert checks["recorder hooks (project)"] == PASS
    assert checks["guard fails closed (project)"] == PASS
    assert checks["hook programs found (project)"] == PASS
    assert checks["checkpoints timestamped (project)"] == PASS
    assert checks["safety-check approvers"] == WARN  # recorder key doubles as approver
    assert checks["recorder key kept off this machine"] == WARN
    assert checks["session r1"] == PASS
    out = runner.invoke(cli, ["doctor", "--recorder", "--out", str(tmp_path / "r.md")])
    assert out.exit_code == 0, out.output
    assert "| PASS | claude code | recorder hooks (project)" in (tmp_path / "r.md").read_text(encoding="utf-8")
