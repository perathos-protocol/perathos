"""The browser verifier (site/verify/core.js) must agree with the Python CLI.

Runs the shared JavaScript logic under Node (18+, which has WebCrypto with
Ed25519) against the sample pack, tampered copies, and freshly exported
packs. Skipped cleanly when Node is not installed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from perathos.canonical import canonical_json
from perathos.evidence import export_evidence_pack, verify_evidence_pack
from perathos.guard import create_precondition, decide
from perathos.recorder import record_hook_event, session_log_path
from perathos.signing import generate_keypair

REPO = Path(__file__).resolve().parent.parent
SITE = REPO / "site"
CORE = SITE / "verify" / "core.js"
HARNESS = SITE / "verify" / "node-verify.mjs"
SAMPLE = SITE / "samples" / "sample-evidence-pack.zip"
SAMPLE_KEY = "d53f11ff38959d472a2e619b346340b44a79866fb8650d96f22ada467f524707"

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def _node_ok() -> bool:
    if NODE is None:
        return False
    out = subprocess.run([NODE, "-e", "process.exit(globalThis.crypto && crypto.subtle ? 0 : 1)"],
                         capture_output=True)
    return out.returncode == 0


def _verify_dir(d: Path, key: str | None = None) -> dict:
    if not _node_ok():
        pytest.skip("this Node has no WebCrypto (needs Node 18+)")
    args = [NODE, str(HARNESS), str(d)] + ([key] if key else [])
    out = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert out.stdout, out.stderr
    res = json.loads(out.stdout)
    assert out.returncode == (0 if res["valid"] else 1)
    return res


def _extract(zip_path: Path, dest: Path) -> Path:
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(dest)
    return dest


# --------------------------------------------------------------------------- #
# Sample pack
# --------------------------------------------------------------------------- #

def test_sample_is_a_copy_of_the_example():
    example = REPO / "examples" / "pocketos_replay" / "sample-evidence-pack.zip"
    assert SAMPLE.read_bytes() == example.read_bytes()


def test_sample_pack_verifies(tmp_path):
    res = _verify_dir(_extract(SAMPLE, tmp_path), SAMPLE_KEY)
    assert res["valid"], res["errors"]
    assert all(c["ok"] for c in res["checks"])
    s = res["stats"]
    assert s["signers"] == [SAMPLE_KEY]
    assert s["anchors_linked"] == s["anchors"] >= 1
    assert {d["decision"] for d in res["destructive"]} == {"blocked", "allowed"}
    allowed = [d for d in res["destructive"] if d["decision"] == "allowed"]
    assert all(d["precondition"].get("intact") for d in allowed)

    py = verify_evidence_pack(SAMPLE, expected_verify_key=SAMPLE_KEY)
    assert py["valid"]
    for k in ("tool_calls", "blocked", "checkpoints", "signed_checkpoints", "sealed_through", "receipts"):
        assert s[k] == py["session"][k], k


def test_tampered_byte_in_session_fails(tmp_path):
    d = _extract(SAMPLE, tmp_path) / "evidence-pack"
    log = d / "session.jsonl"
    raw = bytearray(log.read_bytes())
    i = raw.index(b'"tool":"Bash"') + len(b'"tool":"')
    raw[i] = ord("b")  # Bash -> bash
    log.write_bytes(bytes(raw))
    res = _verify_dir(d.parent)
    assert not res["valid"]
    assert "ERR_FILE_MODIFIED: session.jsonl" in res["errors"]
    assert any(e.startswith("ERR_RECEIPT_HASH") for e in res["errors"])


def test_wrong_expected_key_fails(tmp_path):
    res = _verify_dir(_extract(SAMPLE, tmp_path), "f" * 64)
    assert not res["valid"]
    assert any(e.startswith("ERR_UNEXPECTED_SIGNER") for e in res["errors"])


def test_unlisted_and_missing_files_fail(tmp_path):
    d = _extract(SAMPLE, tmp_path) / "evidence-pack"
    (d / "REPORT.md").unlink()
    (d / "extra.txt").write_text("hi", encoding="utf-8")
    res = _verify_dir(d.parent)
    assert "ERR_MISSING_FILE: REPORT.md" in res["errors"]
    assert "ERR_UNLISTED_FILE: extra.txt" in res["errors"]


def test_edited_manifest_fails(tmp_path):
    d = _extract(SAMPLE, tmp_path) / "evidence-pack"
    m = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
    m["session_id"] = "someone-else"
    (d / "MANIFEST.json").write_text(json.dumps(m), encoding="utf-8")
    res = _verify_dir(d.parent)
    assert "ERR_MANIFEST_HASH: manifest was modified" in res["errors"]


# --------------------------------------------------------------------------- #
# Canonical JSON parity
# --------------------------------------------------------------------------- #

def test_canonical_json_matches_python(tmp_path):
    if not _node_ok():
        pytest.skip("this Node has no WebCrypto (needs Node 18+)")
    cases = [
        {"b": 1, "a": [True, False, None], "c": {"z": "", "y": -12, "x": 2**53 - 1}},
        {"text": "naïve café 日本 \U0001F600   \u007f", "ctrl": "\x00\x01\x1f\b\f\n\r\t\"\\/"},
        {"\U0001F600": 1, "￿": 2, "é": 3, "Z": 4, "a": 5, "": 6},
        {"nested": [{"k": ["v", 1, {"deep": "ü"}]}], "empty": {}, "list": []},
    ]
    src = tmp_path / "cases.json"
    src.write_text(json.dumps(cases, ensure_ascii=True), encoding="utf-8")
    script = (
        f"import {{ canonicalJson }} from {json.dumps(CORE.as_uri())};\n"
        "import { readFileSync } from 'node:fs';\n"
        "const cases = JSON.parse(readFileSync(process.argv[2], 'utf8'));\n"
        "process.stdout.write(Buffer.from(JSON.stringify(cases.map(canonicalJson))).toString('base64'));\n"
    )
    mjs = tmp_path / "canon.mjs"
    mjs.write_text(script, encoding="utf-8")
    out = subprocess.run([NODE, str(mjs), str(src)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    import base64

    got = json.loads(base64.b64decode(out.stdout).decode("utf-8"))
    assert got == [canonical_json(c) for c in cases]


# --------------------------------------------------------------------------- #
# Freshly exported packs: JS and Python must agree
# --------------------------------------------------------------------------- #

SID = "site-1"


def _record(project: Path, sk: str, vk: str, *, stops: int = 1) -> Path:
    tool = "Bäsh-日本-\U0001F600"  # non-ASCII lands in the hashed receipt body
    for n in range(stops):
        cmd = "terraform destroy -auto-approve"
        d = decide("Bash", {"command": cmd}, project, trusted_key=vk)
        record_hook_event({"hook_event_name": "PreToolUse", "session_id": SID, "cwd": str(project),
                           "tool_name": "Bash", "tool_use_id": f"d{n}", "tool_input": {"command": cmd}},
                          guard_decision=d.receipt_field() if d else None)
        record_hook_event({"hook_event_name": "PreToolUse", "session_id": SID, "cwd": str(project),
                           "tool_name": tool, "tool_use_id": f"t{n}", "tool_input": {"q": "ünïcode"}})
        record_hook_event({"hook_event_name": "PostToolUse", "session_id": SID, "cwd": str(project),
                           "tool_name": tool, "tool_use_id": f"t{n}", "tool_input": {"q": "ünïcode"},
                           "tool_response": "ok"})
        record_hook_event({"hook_event_name": "Stop", "session_id": SID, "cwd": str(project)}, signing_key_hex=sk)
    return session_log_path(project, SID)


def test_fresh_pack_with_precondition_agrees_with_python(tmp_path):
    sk, vk = generate_keypair()
    project = tmp_path / "proj"
    project.mkdir()
    log = _record(project, sk, vk)
    create_precondition(project, scope="*", signing_key_hex=sk, manual_reason="snapshot checked — ok ✓")
    cmd = "terraform destroy -auto-approve"
    d = decide("Bash", {"command": cmd}, project, trusted_key=vk)
    record_hook_event({"hook_event_name": "PreToolUse", "session_id": SID, "cwd": str(project),
                       "tool_name": "Bash", "tool_use_id": "z", "tool_input": {"command": cmd}},
                      guard_decision=d.receipt_field() if d else None)
    record_hook_event({"hook_event_name": "Stop", "session_id": SID, "cwd": str(project)}, signing_key_hex=sk)
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=sk, expected_verify_key=vk)
    assert res["valid"]
    js = _verify_dir(_extract(res["zip"], tmp_path / "x"), vk)
    assert js["valid"], js["errors"]
    assert js["stats"]["blocked"] == res["report"]["blocked"] == 1
    allowed = [x for x in js["destructive"] if x["decision"] == "allowed"]
    assert allowed and allowed[0]["precondition"]["manual_reason"] == "snapshot checked — ok ✓"


def test_truncated_log_with_valid_manifest_fails(tmp_path):
    """A log cut back to an earlier checkpoint, re-packed and re-signed: the head witness catches it."""
    sk, vk = generate_keypair()
    project = tmp_path / "proj"
    project.mkdir()
    log = _record(project, sk, vk, stops=2)
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    first_cp = next(i for i, ln in enumerate(lines) if '"kind":"checkpoint"' in ln)
    log.write_text("".join(lines[: first_cp + 1]), encoding="utf-8")
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=sk)
    py = verify_evidence_pack(res["zip"])
    assert not py["valid"] and any(e.startswith("ERR_TRUNCATED") for e in py["errors"])
    js = _verify_dir(_extract(res["zip"], tmp_path / "x"))
    assert not js["valid"]
    assert any(e.startswith("ERR_TRUNCATED") for e in js["errors"])
    assert next(c for c in js["checks"] if c["id"] == "files")["ok"]  # manifest itself is fine


def test_cited_precondition_missing_fails_in_both(tmp_path):
    """An allowed call whose precondition is not in the pack: an error in the CLI and the browser alike."""
    sk, vk = generate_keypair()
    project = tmp_path / "proj"
    project.mkdir()
    log = _record(project, sk, vk)
    create_precondition(project, scope="*", signing_key_hex=sk, manual_reason="snapshot checked")
    cmd = "terraform destroy -auto-approve"
    d = decide("Bash", {"command": cmd}, project, trusted_key=vk)
    record_hook_event({"hook_event_name": "PreToolUse", "session_id": SID, "cwd": str(project),
                       "tool_name": "Bash", "tool_use_id": "z", "tool_input": {"command": cmd}},
                      guard_decision=d.receipt_field() if d else None)
    record_hook_event({"hook_event_name": "Stop", "session_id": SID, "cwd": str(project)}, signing_key_hex=sk)
    shutil.rmtree(project / ".perathos" / "preconditions")
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=sk, expected_verify_key=vk)
    py = verify_evidence_pack(res["zip"], expected_verify_key=vk)
    js = _verify_dir(_extract(res["zip"], tmp_path / "x"), vk)
    assert not py["valid"] and not js["valid"]
    missing = [e for e in js["errors"] if e.startswith("ERR_PRECONDITION_MISSING")]
    assert missing == [e for e in py["errors"] if e.startswith("ERR_PRECONDITION_MISSING")] and len(missing) == 1
    assert not next(c for c in js["checks"] if c["id"] == "preconditions")["ok"]


def test_head_witness_hash_mismatch_fails_in_both(tmp_path):
    """Head witness at a real checkpoint seq but with another hash: ERR_HEAD_MISMATCH in both verifiers."""
    import hashlib

    from perathos.canonical import canonical_bytes
    from perathos.evidence import _sha256_file
    from perathos.signing import sign_hash
    sk, vk = generate_keypair()
    project = tmp_path / "proj"
    project.mkdir()
    log = _record(project, sk, vk)
    res = export_evidence_pack(log, tmp_path / "pack", signing_key_hex=sk, make_zip=False)
    d = res["dir"]
    head = json.loads((d / "session.head.json").read_text(encoding="utf-8"))
    head["receipt_hash"] = "0" * 64
    (d / "session.head.json").write_text(json.dumps(head), encoding="utf-8")
    m = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
    m["files"]["session.head.json"] = _sha256_file(d / "session.head.json")
    body = {k: v for k, v in m.items() if k not in ("manifest_hash", "signature")}
    m["manifest_hash"] = hashlib.sha256(canonical_bytes(body)).hexdigest()
    m["signature"] = sign_hash(m["manifest_hash"], sk)
    (d / "MANIFEST.json").write_text(json.dumps(m), encoding="utf-8")
    py = verify_evidence_pack(d)
    js = _verify_dir(d)
    assert any(e.startswith("ERR_HEAD_MISMATCH") for e in py["errors"]), py["errors"]
    assert any(e.startswith("ERR_HEAD_MISMATCH") for e in js["errors"]), js["errors"]
