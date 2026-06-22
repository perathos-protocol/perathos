"""Regression tests for the enterprise-audit fixes (commit batch after 298fc03).

Each test pins a specific confirmed finding so the fix cannot silently regress.
"""
import json

import pytest

from perathos.bundle import create_bundle
from perathos.canonical import canonical_bytes, canonical_json
from perathos.inspector import inspect_bundle
from perathos.pipeline import CONJUNCTION, QUORUM, WEIGHTED, MultiVerifierPipeline, verify_output
from perathos.signing import generate_keypair, sign_hash, verify_signature
from perathos.verdict import (
    FAIL,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    PASS,
    WARN,
    VerdictRecord,
)
from perathos.verifiers import VerificationContext, Verifier


class _Fixed(Verifier):
    """A verifier that always returns a preset verdict — for aggregation tests."""

    def __init__(self, vid, verdict, conf=500):
        self.verifier_id = vid
        self.verifier_name = f"fixed-{vid}"
        self.verifier_version = "0"
        self.method = "test"
        self._verdict = verdict
        self._conf = conf

    def _verify(self, output, ctx):
        return self._record(self._verdict, self._conf, "fixed")


def _agg(verifiers, mode):
    return MultiVerifierPipeline(verifiers, mode=mode).run("x", VerificationContext()).aggregate


# ── #5 canonical serialization strictness ─────────────────────────────────────

def test_canonical_rejects_nan_and_infinity():
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical_bytes({"x": bad})


def test_canonical_rejects_non_string_keys():
    with pytest.raises(ValueError):
        canonical_bytes({1: "a"})
    with pytest.raises(ValueError):
        canonical_bytes({"nested": {2: "b"}})


def test_canonical_output_parses_strictly():
    out = canonical_json({"b": 2, "a": [1, {"c": "x"}]})
    # A strict loader that forbids NaN/Infinity constants must accept the output.
    parsed = json.loads(out, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    assert parsed == {"b": 2, "a": [1, {"c": "x"}]}


# ── #8 / #9 signature algorithm + strict hex ──────────────────────────────────

def test_verify_signature_rejects_unsupported_algorithm():
    sk, vk = generate_keypair()
    h = "a" * 64
    sig = sign_hash(h, sk)
    sig["algorithm"] = "rsa"
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert err == "ERR_UNSUPPORTED_ALGORITHM"


def test_verify_signature_rejects_uppercase_signature_hex():
    sk, vk = generate_keypair()
    h = "a" * 64
    sig = sign_hash(h, sk)
    sig["signature"] = sig["signature"].upper()
    valid, err = verify_signature(h, sig)
    assert valid is False
    assert "ERR_INVALID_SIGNATURE" in err


def test_validly_signed_still_verifies():
    sk, vk = generate_keypair()
    h = "a" * 64
    sig = sign_hash(h, sk)
    assert verify_signature(h, sig) == (True, "")


# ── #2 QUORUM / WEIGHTED aggregation ──────────────────────────────────────────

def test_quorum_met_pass():
    agg = _agg([_Fixed(1, PASS, 800), _Fixed(2, PASS, 600), _Fixed(3, PASS, 900)], QUORUM)
    assert agg["verdict"] == PASS
    assert agg["confidence_bps"] == 600  # min over the driving (pass) records


def test_quorum_met_with_warn_is_warn():
    agg = _agg([_Fixed(1, PASS), _Fixed(2, PASS), _Fixed(3, WARN, 300)], QUORUM)
    assert agg["verdict"] == WARN
    assert agg["confidence_bps"] == 300


def test_quorum_not_met_is_warn():
    agg = _agg([_Fixed(1, PASS), _Fixed(2, WARN), _Fixed(3, WARN)], QUORUM)
    assert agg["verdict"] == WARN
    assert "no quorum" in agg["rationale"]


def test_quorum_fail_dominates():
    agg = _agg([_Fixed(1, PASS), _Fixed(2, PASS), _Fixed(3, FAIL, 700)], QUORUM)
    assert agg["verdict"] == FAIL
    assert agg["confidence_bps"] == 700


def test_weighted_behaves_like_quorum_here():
    agg = _agg([_Fixed(1, PASS), _Fixed(2, PASS), _Fixed(3, PASS)], WEIGHTED)
    assert agg["verdict"] == PASS


# ── #14 not_applicable_count reconciles ───────────────────────────────────────

def test_aggregate_counts_reconcile():
    agg = _agg([_Fixed(1, PASS), _Fixed(2, NOT_APPLICABLE), _Fixed(3, INCONCLUSIVE)], CONJUNCTION)
    assert agg["not_applicable_count"] == 1
    assert agg["inconclusive_count"] == 1
    assert agg["pass_count"] == 1
    total = agg["pass_count"] + agg["fail_count"] + agg["warn_count"] + agg["inconclusive_count"] + agg["not_applicable_count"]
    assert total == agg["total_count"] == 3


# ── #11 verify_output arg order + verifier validation ─────────────────────────

def test_verify_output_input_text_is_second_positional():
    # The 2nd positional is input_text (matching create_bundle), NOT verifiers.
    bundle = verify_output("the answer", "the prompt")
    assert bundle["input_hash"] == create_bundle("the answer", "the prompt")["input_hash"]


def test_pipeline_rejects_non_verifier():
    with pytest.raises(TypeError):
        MultiVerifierPipeline(["not a verifier"])


# ── #18 VerdictRecord validation / clamping ───────────────────────────────────

def test_verdict_record_rejects_invalid_verdict():
    with pytest.raises(ValueError):
        VerdictRecord(1, "n", "v", "BOGUS")


def test_verdict_record_clamps_confidence():
    assert VerdictRecord(1, "n", "v", PASS, confidence_bps=-5).confidence_bps == 0
    assert VerdictRecord(1, "n", "v", PASS, confidence_bps=99999).confidence_bps == 1000


def test_verdict_record_to_dict_keys():
    d = VerdictRecord(1, "n", "v", PASS).to_dict()
    assert set(d) == {
        "verifier_id", "verifier_name", "verifier_version", "verdict",
        "confidence_bps", "method", "detail", "evidence_digests", "computed",
    }


# ── #6 / #7 / #17 inspector never crashes on malformed/foreign bundles ─────────

@pytest.mark.parametrize("mutate", [
    lambda b: b.update(verification="not a dict"),
    lambda b: b.update(verification={"aggregate": 5, "verdict_records": "x"}),
    lambda b: b.update(verification={"aggregate": {}, "verdict_records": [
        {"verifier_id": 1, "verifier_name": "[/bold][red]x", "verdict": "[/]", "confidence_bps": "junk", "detail": "[bold]", "evidence_digests": "nope"}]}),
    lambda b: b.update(_trace=12345),
    lambda b: b.update(_trace={"model_descriptor": 999}),
    lambda b: b.pop("input_hash", None),
    lambda b: b.update(issued_at="not-a-timestamp"),
])
def test_inspect_never_crashes_on_malformed_bundle(mutate, capsys):
    b = create_bundle("output", input_text="in")
    mutate(b)
    inspect_bundle(b)  # must not raise
    out = capsys.readouterr().out
    assert len(out) > 0


def test_inspect_renders_real_verification_block(capsys):
    out = "The capital of France is Paris."
    ctx = VerificationContext(samples=[out, out], evidence=[out])
    inspect_bundle(verify_output(out, context=ctx))
    captured = capsys.readouterr().out
    assert "Verification" in captured
    assert "PASS" in captured
