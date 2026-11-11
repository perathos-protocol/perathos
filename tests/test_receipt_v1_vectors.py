"""The published perathos.receipt/v1 interop vectors: verdicts and reproducibility."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.cli import cli
from perathos.recorder import verify_session

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "docs" / "specs" / "vectors" / "receipt_v1"
EXPECTED = json.loads((VECTORS / "expected.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
GENERATED = ["expected.json"] + [
    f"{name}/{fname}"
    for name in CASES
    for fname in EXPECTED["cases"][name]["files"].values()
]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "make_receipt_v1_vectors", ROOT / "scripts" / "make_receipt_v1_vectors.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """No ~/.perathos anchors or error log from this machine may leak into the result."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def test_four_cases_published():
    assert CASES == [
        "01-valid",
        "02-broken-prev-hash",
        "03-forged-checkpoint-signature",
        "04-unsigned-checkpoint",
    ]


@pytest.mark.parametrize("name", CASES)
def test_library_verdict(name):
    case = EXPECTED["cases"][name]
    report = verify_session(
        VECTORS / name / case["files"]["log"],
        expected_verify_key=EXPECTED["verify_key"],
    )
    assert report.valid is (case["verdict"] == "VALID")
    assert report.errors == [e["message"] for e in case["errors"]]
    for err, msg in zip(case["errors"], report.errors):
        assert msg.startswith(f"{err['code']} at seq {err['seq']} ")
    assert report.warnings == []


@pytest.mark.parametrize("name", CASES)
def test_cli_verdict(name, isolated_home):
    case = EXPECTED["cases"][name]
    log = VECTORS / name / case["files"]["log"]
    result = CliRunner().invoke(
        cli, ["session", "verify", str(log), "--verify-key", EXPECTED["verify_key"]]
    )
    assert result.exit_code == (0 if case["verdict"] == "VALID" else 1), result.output
    assert result.output.splitlines()[0] == f"{case['verdict']}  {log}"
    for err in case["errors"]:
        assert f"[ERROR] {err['message']}" in result.output


def test_unsigned_case_passes_when_unsigned_allowed(isolated_home):
    case = EXPECTED["cases"]["04-unsigned-checkpoint"]
    log = VECTORS / "04-unsigned-checkpoint" / case["files"]["log"]
    result = CliRunner().invoke(
        cli,
        [
            "session",
            "verify",
            str(log),
            "--verify-key",
            EXPECTED["verify_key"],
            "--allow-unsigned",
        ],
    )
    assert result.exit_code == 0, result.output
    assert (
        result.output.splitlines()[0] == f"{case['verdict_with_allow_unsigned']}  {log}"
    )


def test_signature_encoding_matches_spec():
    """signature.signature is 128 lowercase hex chars, Ed25519 over the raw 32 bytes of receipt_hash."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    lines = (
        (VECTORS / "01-valid" / "receipt-v1-vector.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    checkpoints = [r for r in map(json.loads, lines) if r["kind"] == "checkpoint"]
    assert len(checkpoints) == 2
    for cp in checkpoints:
        sig = cp["signature"]
        assert (
            len(sig["signature"]) == 128
            and sig["signature"] == sig["signature"].lower()
        )
        assert sig["verify_key"] == cp["signer"] == EXPECTED["verify_key"]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["verify_key"])).verify(
            bytes.fromhex(sig["signature"]), bytes.fromhex(cp["receipt_hash"])
        )


def test_generator_is_byte_identical(tmp_path):
    gen = _load_generator()
    out = tmp_path / "receipt_v1"
    gen.generate(out)
    produced = sorted(
        p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()
    )
    assert produced == sorted(GENERATED)
    for rel in GENERATED:
        assert (out / rel).read_bytes() == (VECTORS / rel).read_bytes(), rel
