"""The published Bundle v2 commerce-event vectors (NEXUS trust record): verdicts and reproducibility."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from perathos.bundle import PERATHOS_NAMESPACE, verify_bundle
from perathos.canonical import canonical_bytes
from perathos.cli import cli
from perathos.keytrust import TrustStore, kid_for

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "docs" / "specs" / "vectors" / "bundle_v2"
EXPECTED = json.loads((VECTORS / "expected.json").read_text(encoding="utf-8"))
JWKS = json.loads((VECTORS / "jwks.json").read_text(encoding="utf-8"))
CASES = sorted(EXPECTED["cases"])
VALID = [n for n in CASES if EXPECTED["cases"][n]["python"]["verdict"] == "VALID"]
GENERATED = ["expected.json", "jwks.json"] + [
    EXPECTED["cases"][n]["file"] for n in CASES
]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "make_bundle_v2_vectors", ROOT / "scripts" / "make_bundle_v2_vectors.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _bundle(name: str) -> dict:
    return json.loads(
        (VECTORS / EXPECTED["cases"][name]["file"]).read_text(encoding="utf-8")
    )


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_cases_published():
    assert CASES == [
        "01-order-confirmed",
        "02-order-shipped",
        "03-order-delivered",
        "04-dispute-closed",
        "10-answer-edited",
        "11-output-hash-edited",
        "12-trace-edited",
        "13-bundle-id-edited",
        "14-forged-signature",
        "15-signature-removed",
        "16-algorithm-changed",
        "17-untrusted-signer",
        "18-answer-stripped",
        "19-chain-broken",
    ]


def test_jwks_holds_only_the_trusted_key():
    trusted = EXPECTED["keys"]["trusted"]
    assert (
        JWKS
        == TrustStore().add_public_key(bytes.fromhex(trusted["verify_key"])).to_jwks()
    )
    assert (
        JWKS["keys"][0]["kid"]
        == trusted["kid"]
        == kid_for(bytes.fromhex(trusted["verify_key"]))
    )
    assert EXPECTED["perathos_namespace"] == str(PERATHOS_NAMESPACE)


@pytest.mark.parametrize("name", CASES)
def test_library_verdict(name):
    want = EXPECTED["cases"][name]["python"]
    got = verify_bundle(
        _bundle(name), trust_store=TrustStore.from_jwks(JWKS), require_signed=True
    )
    assert got == (want["verdict"] == "VALID", want["code"])


@pytest.mark.parametrize("name", CASES)
def test_recorded_intermediates_are_consistent(name):
    """Recompute every recorded intermediate from the recorded inputs (independently of the generator)."""
    b = EXPECTED["cases"][name]["build"]
    payload_bytes = canonical_bytes(b["payload"])
    assert payload_bytes.decode("utf-8") == b["payload_canonical"]
    assert payload_bytes.hex() == b["payload_canonical_hex"]
    assert canonical_bytes(b["_trace"]).decode("utf-8") == b["trace_canonical"]
    assert b["_trace"] == {
        "model_descriptor": EXPECTED["model_descriptor"],
        "proof_system": EXPECTED["proof_system"],
        "input_length": len(b["input_text"]),
        "output_length": len(b["payload_canonical"]),
    }
    assert b["trace_hash"] == _sha(canonical_bytes(b["_trace"]))
    assert b["ai_id"] == _sha(EXPECTED["model_descriptor"].encode("utf-8"))
    assert b["input_hash"] == _sha(b["input_text"].encode("utf-8"))
    assert b["output_hash"] == _sha(payload_bytes)
    ip = b["integrity_payload"]
    assert ip == {
        "ai_id": b["ai_id"],
        "input_hash": b["input_hash"],
        "issued_at": b["issued_at"],
        "output_hash": b["output_hash"],
        "proof_system": EXPECTED["proof_system"],
        "trace_hash": b["trace_hash"],
        "bundle_version": "2.0",
        "model": EXPECTED["model"],
    }
    assert canonical_bytes(ip).decode("utf-8") == b["integrity_payload_canonical"]
    assert canonical_bytes(ip).hex() == b["integrity_payload_canonical_hex"]
    assert b["integrity_hash"] == _sha(canonical_bytes(ip))
    assert b["bundle_id"] == str(uuid.uuid5(PERATHOS_NAMESPACE, b["integrity_hash"]))
    assert (
        b["provider_signature"]["verify_key"]
        == EXPECTED["keys"][b["signer"]]["verify_key"]
    )


@pytest.mark.parametrize(
    "name", [n for n in CASES if EXPECTED["cases"][n]["mutation"] is None]
)
def test_unmutated_bundle_matches_its_build(name):
    b = EXPECTED["cases"][name]["build"]
    bundle = _bundle(name)
    for field in (
        "bundle_id",
        "issued_at",
        "ai_id",
        "input_hash",
        "output_hash",
        "trace_hash",
        "integrity_hash",
        "_trace",
        "provider_signature",
    ):
        assert bundle[field] == b[field], field
    assert bundle["answer"] == b["payload_canonical"]
    assert bundle["model"] == EXPECTED["model"]


def _chain_error(names: list[str]) -> str:
    """A minimal chain walk, as NEXUS does it: seq 1.., input_hash links."""
    prev_id = ""
    for i, name in enumerate(names, start=1):
        bundle = _bundle(name)
        if json.loads(bundle["answer"])["seq"] != i or bundle["input_hash"] != _sha(
            prev_id.encode()
        ):
            return "ERR_CHAIN"
        prev_id = bundle["bundle_id"]
    return ""


def test_chains():
    assert _chain_error(EXPECTED["chains"]["valid"]) == ""
    assert _chain_error(EXPECTED["chains"]["broken"]) == "ERR_CHAIN"
    assert EXPECTED["cases"]["19-chain-broken"]["nexus"] == {
        "verdict": "INVALID",
        "code": "ERR_CHAIN",
    }
    assert EXPECTED["cases"]["18-answer-stripped"]["nexus"] == {
        "verdict": "INVALID",
        "code": "ERR_ANSWER_REQUIRED",
    }
    assert "answer" not in _bundle("18-answer-stripped")


@pytest.mark.parametrize("name", CASES)
def test_cli_verdict(name):
    bundle = VECTORS / EXPECTED["cases"][name]["file"]
    result = CliRunner().invoke(
        cli,
        ["verify", "--file", str(bundle), "--trust-jwks", str(VECTORS / "jwks.json")],
    )
    valid = EXPECTED["cases"][name]["python"]["verdict"] == "VALID"
    assert result.exit_code == (0 if valid else 1), result.output
    if valid:
        assert result.output.splitlines()[0] == f"VALID_SIGNED  {bundle}"


def test_valid_cases_pass_cli():
    assert VALID == [
        "01-order-confirmed",
        "02-order-shipped",
        "03-order-delivered",
        "04-dispute-closed",
        "18-answer-stripped",
        "19-chain-broken",
    ]


def test_generator_is_byte_identical(tmp_path):
    gen = _load_generator()
    out = tmp_path / "bundle_v2"
    gen.generate(out)
    produced = sorted(
        p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()
    )
    assert produced == sorted(GENERATED)
    for rel in GENERATED:
        assert (out / rel).read_bytes() == (VECTORS / rel).read_bytes(), rel
