"""Tests for the Proof Bundle v2 format and v1 dual-read compatibility."""
import copy

from perathos.bundle import BUNDLE_VERSION, create_bundle, verify_bundle
from perathos.pipeline import verify_output
from perathos.verifiers import VerificationContext


# ── v2 is the default ─────────────────────────────────────────────────────────

def test_default_is_v2():
    b = create_bundle("output", model="gpt-x")
    assert b["bundle_version"] == BUNDLE_VERSION
    assert b["model"] == "gpt-x"
    assert verify_bundle(b) == (True, "")


def test_v2_records_carry_computed_flag():
    out = "The capital of France is Paris."
    b = verify_output(out, context=VerificationContext(samples=[out]))
    assert all("computed" in r for r in b["verification"]["verdict_records"])
    assert b["verdict"] == b["verification"]["aggregate"]["verdict"]
    assert verify_bundle(b) == (True, "")


def test_v2_model_tamper_breaks_integrity():
    b = create_bundle("output", model="trusted-model")
    t = copy.deepcopy(b)
    t["model"] = "evil-model"
    valid, err = verify_bundle(t)
    assert valid is False
    assert err == "ERR_INTEGRITY_HASH_MISMATCH"


def test_v2_top_level_verdict_tamper_detected():
    out = "x"
    b = verify_output(out, context=VerificationContext(samples=[out]))
    t = copy.deepcopy(b)
    t["verdict"] = "PASS" if t["verdict"] != "PASS" else "FAIL"
    valid, err = verify_bundle(t)
    assert valid is False
    assert err == "ERR_VERDICT_MISMATCH"


# ── optional answer (hash-only by default) ────────────────────────────────────

def test_answer_omitted_by_default():
    assert "answer" not in create_bundle("secret output")


def test_include_answer_is_bound_and_verifies():
    b = create_bundle("the answer text", include_answer=True)
    assert b["answer"] == "the answer text"
    assert verify_bundle(b) == (True, "")


def test_answer_tamper_detected():
    b = create_bundle("the answer text", include_answer=True)
    t = copy.deepcopy(b)
    t["answer"] = "a forged answer"
    valid, err = verify_bundle(t)
    assert valid is False
    assert err == "ERR_ANSWER_MISMATCH"


# ── v1 dual-read compatibility ────────────────────────────────────────────────

def test_v1_bundle_still_verifies():
    # A bundle minted under the v1 format (no bundle_version) must still verify.
    b = create_bundle("output", input_text="in", bundle_version="1.0")
    assert "bundle_version" not in b
    assert "model" not in b
    assert verify_bundle(b) == (True, "")


def test_v1_signed_bundle_still_verifies():
    from perathos.bundle import sign_bundle
    from perathos.signing import generate_keypair
    sk, vk = generate_keypair()
    b = sign_bundle(create_bundle("output", bundle_version="1.0"), sk)
    assert verify_bundle(b, expected_verify_key=vk) == (True, "")


def test_v1_tamper_still_detected():
    b = create_bundle("output", bundle_version="1.0")
    t = copy.deepcopy(b)
    t["output_hash"] = "a" * 64
    valid, err = verify_bundle(t)
    assert valid is False
    assert "ERR" in err
