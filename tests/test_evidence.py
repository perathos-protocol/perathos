"""Evidence packs: export, independent re-verification, tamper detection; demo smoke test."""
from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from perathos.evidence import export_evidence_pack, verify_evidence_pack
from perathos.guard import create_precondition, decide
from perathos.recorder import record_hook_event, session_log_path
from perathos.signing import generate_keypair

SID = "ev-1"
REPO = Path(__file__).resolve().parent.parent


def _session(project: Path, sk: str, vk: str) -> Path:
    def pre(tid, cmd):
        d = decide("Bash", {"command": cmd}, project, trusted_key=vk)
        record_hook_event({"hook_event_name": "PreToolUse", "session_id": SID, "cwd": str(project),
                           "tool_name": "Bash", "tool_use_id": tid, "tool_input": {"command": cmd}},
                          guard_decision=d.receipt_field() if d else None)
        return d

    pre("t1", "terraform destroy -auto-approve")  # denied
    create_precondition(project, scope="*", signing_key_hex=sk, manual_reason="snapshot verified by on-call")
    pre("t2", "terraform destroy -auto-approve")  # allowed
    record_hook_event({"hook_event_name": "PostToolUse", "session_id": SID, "cwd": str(project), "tool_name": "Bash",
                       "tool_use_id": "t2", "tool_input": {"command": "terraform destroy -auto-approve"},
                       "tool_response": "Destroy complete!"})
    record_hook_event({"hook_event_name": "Stop", "session_id": SID, "cwd": str(project)}, signing_key_hex=sk)
    return session_log_path(project, SID)


@pytest.fixture
def pack(tmp_path):
    sk, vk = generate_keypair()
    project = tmp_path / "proj"
    project.mkdir()
    log = _session(project, sk, vk)
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=sk, expected_verify_key=vk)
    return res, vk


def test_export_contents_and_summary(pack):
    res, vk = pack
    d = res["dir"]
    assert res["valid"], res["report"]["errors"]
    for name in ("session.jsonl", "session.head.json", "verification.json", "REPORT.md", "REPORT.html",
                 "VERIFY.md", "MANIFEST.json"):
        assert (d / name).exists(), name
    assert len(list((d / "preconditions").glob("*.json"))) == 1
    rep = res["report"]
    assert rep["blocked"] == 1 and len(rep["blocked_calls"]) == 1
    allowed = rep["allowed_under_precondition"]
    assert len(allowed) == 1 and allowed[0]["precondition"]["manual_reason"] == "snapshot verified by on-call"
    assert "blocked by the guard: 1" in (d / "REPORT.md").read_text(encoding="utf-8")
    assert vk in (d / "VERIFY.md").read_text(encoding="utf-8")
    assert "Destroy complete" not in (d / "session.jsonl").read_text(encoding="utf-8")  # hashes only


def test_pack_verifies_from_dir_and_zip(pack):
    res, vk = pack
    assert verify_evidence_pack(res["dir"], expected_verify_key=vk)["valid"]
    assert verify_evidence_pack(res["zip"], expected_verify_key=vk)["valid"]
    bad = verify_evidence_pack(res["dir"], expected_verify_key="f" * 64)
    assert not bad["valid"]


def test_modified_file_detected(pack):
    res, _ = pack
    rpt = res["dir"] / "REPORT.md"
    rpt.write_text(rpt.read_text(encoding="utf-8").replace("VALID", "VALID (edited)"), encoding="utf-8")
    out = verify_evidence_pack(res["dir"])
    assert not out["valid"] and any("ERR_FILE_MODIFIED: REPORT.md" in e for e in out["errors"])


def test_added_and_removed_files_detected(pack):
    res, _ = pack
    (res["dir"] / "extra.txt").write_text("x", encoding="utf-8")
    out = verify_evidence_pack(res["dir"])
    assert any("ERR_UNLISTED_FILE: extra.txt" in e for e in out["errors"])
    (res["dir"] / "extra.txt").unlink()
    (res["dir"] / "VERIFY.md").unlink()
    out = verify_evidence_pack(res["dir"])
    assert any("ERR_MISSING_FILE: VERIFY.md" in e for e in out["errors"])


def test_truncated_log_in_pack_detected(pack):
    res, _ = pack
    log = res["dir"] / "session.jsonl"
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    out = verify_evidence_pack(res["dir"])
    assert not out["valid"]  # manifest hash and the head witness both catch it
    assert any("session.jsonl" in e for e in out["errors"])


def test_unsigned_manifest_rejected(tmp_path):
    sk, vk = generate_keypair()
    project = tmp_path / "p"
    project.mkdir()
    log = _session(project, sk, vk)
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=None, make_zip=False)
    out = verify_evidence_pack(res["dir"])
    assert not out["valid"] and any("ERR_MANIFEST_UNSIGNED" in e for e in out["errors"])


def test_zip_slip_rejected(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../escape.txt", "x")
    with pytest.raises(ValueError):
        verify_evidence_pack(z)


def test_pocketos_replay_demo_runs_offline(tmp_path):
    """The public demo must keep working: run it end to end without network."""
    out_json = tmp_path / "replay.json"
    r = subprocess.run([sys.executable, str(REPO / "examples" / "pocketos_replay" / "replay.py"), "--offline",
                        "--out", str(tmp_path / "out"), "--json", str(out_json)],
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    text = r.stdout
    assert "production database: GONE; backups: on-volume=GONE, off-site=none" in text  # run A
    assert text.count("BLOCKED by perathos guard") == 2
    assert "check FAILED, no precondition created" in text
    assert "restore from the off-site backup: 1200 customers" in text
    assert "independent re-check of the pack: VALID" in text
    events = json.loads(out_json.read_text(encoding="utf-8"))["events"]
    assert len(events) > 20


def test_tampered_precondition_in_pack_detected(pack):
    """Even with the manifest re-signed by an attacker, a forged precondition fails."""
    import hashlib

    from perathos.canonical import canonical_bytes
    from perathos.signing import sign_hash
    res, _ = pack
    f = next((res["dir"] / "preconditions").glob("*.json"))
    pc = json.loads(f.read_text(encoding="utf-8"))
    pc["manual_reason"] = "edited after the fact"
    f.write_text(json.dumps(pc), encoding="utf-8")
    # re-sign the manifest with another key so only the precondition check can catch it
    m = json.loads((res["dir"] / "MANIFEST.json").read_text(encoding="utf-8"))
    from perathos.evidence import _sha256_file
    m["files"][f"preconditions/{f.name}"] = _sha256_file(f)
    body = {k: v for k, v in m.items() if k not in ("manifest_hash", "signature")}
    m["manifest_hash"] = hashlib.sha256(canonical_bytes(body)).hexdigest()
    m["signature"] = sign_hash(m["manifest_hash"], generate_keypair()[0])
    (res["dir"] / "MANIFEST.json").write_text(json.dumps(m), encoding="utf-8")
    out = verify_evidence_pack(res["dir"])
    assert any("ERR_PRECONDITION_MODIFIED" in e for e in out["errors"])
