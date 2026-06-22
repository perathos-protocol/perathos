"""Tests for the ported real verifier engines."""
from perathos.engines import (
    HallucinationDetector,
    SchemaValidator,
    SymbolicSolver,
    TemporalConsistency,
)
from perathos.verdict import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS
from perathos.verifiers import VerificationContext


def _v(engine, output, **ctx):
    return engine.run(output, VerificationContext(**ctx))


# ── SymbolicSolver (123) ──────────────────────────────────────────────────────

def test_symbolic_pass():
    r = _v(SymbolicSolver(), "The total is 2 + 2 = 4 and 10 * 5 = 50.")
    assert r.verdict == PASS
    assert r.evidence_digests  # the recomputation trace is bound


def test_symbolic_fail():
    r = _v(SymbolicSolver(), "Clearly 2 + 2 = 5.")
    assert r.verdict == FAIL
    assert r.confidence_bps == 1000


def test_symbolic_skipped_no_math():
    assert _v(SymbolicSolver(), "Paris is the capital of France.").verdict == NOT_APPLICABLE


def test_symbolic_hex_before_x_multiply():
    # "0x10 = 16" must read 0x10 as 16 (hex), not 0*10=0. (Audit regression.)
    assert _v(SymbolicSolver(), "0x10 = 16").verdict == PASS


# ── HallucinationDetector (125) ───────────────────────────────────────────────

def test_grounding_pass():
    r = _v(HallucinationDetector(), "The refund window is 30 days.",
           sources=["Refunds are available within 30 days of purchase."])
    assert r.verdict == PASS


def test_grounding_fail_fabricated_specific():
    r = _v(HallucinationDetector(), "You get a $500 refund within 90 days.",
           sources=["Refunds are available within 30 days; no cash refunds."])
    assert r.verdict == FAIL


def test_grounding_skipped_no_sources():
    assert _v(HallucinationDetector(), "The refund is $50.").verdict == NOT_APPLICABLE


def test_grounding_entailment_fail_closed_on_error():
    def boom(answer, sources):
        raise RuntimeError("model down")
    # No extractive specifics + entailment error -> must NOT pass; stays skipped.
    r = HallucinationDetector(entailment_fn=boom).run(
        "Paraphrased claim with no specifics.",
        VerificationContext(sources=["Some grounding text."]))
    assert r.verdict in (NOT_APPLICABLE, FAIL)


# ── SchemaValidator (126) ─────────────────────────────────────────────────────

def test_schema_pass():
    schema = {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}
    assert _v(SchemaValidator(), '{"name": "ok"}', schema=schema).verdict == PASS


def test_schema_fail_missing_required():
    schema = {"type": "object", "required": ["name"]}
    assert _v(SchemaValidator(), '{"other": 1}', schema=schema).verdict == FAIL


def test_schema_skipped_no_schema():
    assert _v(SchemaValidator(), '{"x": 1}').verdict == NOT_APPLICABLE


def test_schema_refuses_remote_ref():
    # A remote $ref must be refused (SSRF guard) -> error/INCONCLUSIVE, not a hang.
    schema = {"$ref": "http://169.254.169.254/latest/meta-data/"}
    r = _v(SchemaValidator(), '{"x": 1}', schema=schema)
    assert r.verdict == INCONCLUSIVE


# ── TemporalConsistency (127) ─────────────────────────────────────────────────

def test_temporal_pass():
    assert _v(TemporalConsistency(), "The internet became widespread in 1995.").verdict == PASS


def test_temporal_fail_anachronism():
    assert _v(TemporalConsistency(), "In 1850 he sent a text message from his smartphone.").verdict == FAIL


def test_temporal_skipped():
    assert _v(TemporalConsistency(), "It was a sunny day.").verdict == NOT_APPLICABLE


def test_temporal_word_boundary_no_false_fire():
    # "scared" must not trigger the "car" (1886) term. (Audit regression.)
    assert _v(TemporalConsistency(), "In 1850 she was scared of the dark.").verdict == NOT_APPLICABLE
