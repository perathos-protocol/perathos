"""Tests that the verification block is correctly bound into the proof bundle:
tamper-evident, signable, and backward compatible with unverified bundles.
"""
import copy

from perathos.bundle import create_bundle, sign_bundle, verify_bundle
from perathos.pipeline import verify_output
from perathos.signing import generate_keypair
from perathos.verifiers import VerificationContext


def _ctx():
    out = "The capital of France is Paris."
    return out, VerificationContext(
        samples=[out, "Paris is the capital of France."],
        evidence=["The capital of France is Paris."],
    )


def test_backward_compat_unverified_bundle_unchanged():
    """A bundle created without verification must have no verification key and
    still verify exactly as before (no verification_hash in the integrity root)."""
    b = create_bundle("hello", input_text="hi")
    assert "verification" not in b
    valid, err = verify_bundle(b)
    assert valid is True and err == ""


def test_verified_bundle_verifies():
    out, ctx = _ctx()
    bundle = verify_output(out, context=ctx)
    assert "verification" in bundle
    assert bundle["verification"]["aggregate"]["verdict"] in ("PASS", "WARN", "FAIL")
    valid, err = verify_bundle(bundle)
    assert valid is True, err


def test_tampering_with_a_verdict_breaks_integrity():
    out, ctx = _ctx()
    bundle = verify_output(out, context=ctx)
    tampered = copy.deepcopy(bundle)
    # Forge the aggregate verdict (to a value different from the real one)
    # without re-deriving the integrity hash.
    tampered["verification"]["aggregate"]["verdict"] = "FORGED_PASS"
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert err == "ERR_INTEGRITY_HASH_MISMATCH"


def test_stripping_verification_breaks_integrity():
    """Removing the verification block from a verified bundle is detected."""
    out, ctx = _ctx()
    bundle = verify_output(out, context=ctx)
    stripped = {k: v for k, v in bundle.items() if k != "verification"}
    valid, err = verify_bundle(stripped)
    assert valid is False
    assert err == "ERR_INTEGRITY_HASH_MISMATCH"


def test_adding_verification_to_unverified_bundle_breaks_integrity():
    """Injecting a verification block into a plain bundle is detected."""
    b = create_bundle("hello")
    b["verification"] = {"schema": "vrl/verification/1", "aggregate": {"verdict": "PASS"}, "verdict_records": []}
    valid, err = verify_bundle(b)
    assert valid is False
    assert err == "ERR_INTEGRITY_HASH_MISMATCH"


def test_evidence_digest_tamper_is_detected():
    out, ctx = _ctx()
    bundle = verify_output(out, context=ctx)
    tampered = copy.deepcopy(bundle)
    recs = tampered["verification"]["verdict_records"]
    # find a record that actually has evidence digests
    for r in recs:
        if r["evidence_digests"]:
            r["evidence_digests"][0] = "sha-256:" + "0" * 64
            break
    valid, err = verify_bundle(tampered)
    assert valid is False
    assert err == "ERR_INTEGRITY_HASH_MISMATCH"


def test_verified_bundle_can_be_signed_and_verified():
    out, ctx = _ctx()
    bundle = verify_output(out, context=ctx)
    sk, vk = generate_keypair()
    signed = sign_bundle(bundle, sk)
    valid, err = verify_bundle(signed, expected_verify_key=vk)
    assert valid is True, err


def test_create_bundle_rejects_non_dict_verification():
    try:
        create_bundle("x", verification="not a dict")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "verification" in str(exc)
