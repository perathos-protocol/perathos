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


def test_symbolic_modulo():
    # Modulo is now parseable (regex includes %, evaluator supports ast.Mod).
    assert _v(SymbolicSolver(), "Remainder: 17 % 5 = 2.").verdict == PASS
    assert _v(SymbolicSolver(), "Remainder: 17 % 5 = 3.").verdict == FAIL
    # A bare percentage can't form a binary expr -> skipped, never false-flagged.
    assert _v(SymbolicSolver(), "Growth was 3.2% this year.").verdict == NOT_APPLICABLE


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


def test_grounding_substring_collision_is_caught():
    # gap #2: "90 days" must NOT be grounded by an unrelated "$90" in the source.
    # A duration is checked only against source durations (like-with-like).
    r = _v(HallucinationDetector(), "You may return it within 90 days.",
           sources=["Returns within 30 days. A late fee of $90 applies after that."])
    assert r.verdict == FAIL


def test_grounding_kind_aware_does_not_overflag():
    # Like-with-like must still PASS legitimately grounded specifics, including
    # normalized amounts ($1000 vs $1,000.00) and durations with an inner word.
    assert _v(HallucinationDetector(), "Your balance is $1000.",
              sources=["Records show a balance of $1,000.00 on file."]).verdict == PASS
    assert _v(HallucinationDetector(), "Shipping takes 5 business days.",
              sources=["Standard shipping takes 5 business days."]).verdict == PASS


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


def test_temporal_expanded_terms_catch_anachronism():
    # gap #3: terms added to the curated timeline are now checkable, so
    # off-timeline anachronisms that were silently skipped are caught.
    assert _v(TemporalConsistency(), "She checked her smartwatch in 1850.").verdict == FAIL
    assert _v(TemporalConsistency(), "He scanned the QR code in 1900.").verdict == FAIL


def test_temporal_expanded_terms_pass_when_consistent():
    # And a consistent modern pairing still passes (conservative dates).
    assert _v(TemporalConsistency(), "She checked her smartwatch in 2020.").verdict == PASS


# ── Adversarial hardening (0.2.4): format / encoding / evasion / injection ─────

def test_symbolic_ambiguous_fails_closed_never_false_flags():
    # Scientific notation, caret powers, and decimal commas are AMBIGUOUS — the
    # engine must SKIP (NOT_APPLICABLE), never recompute a fragment and FAIL a
    # correct answer. (Probe found these as false positives.)
    assert _v(SymbolicSolver(), "The total is 2e3 = 2000.").verdict == NOT_APPLICABLE
    assert _v(SymbolicSolver(), "Compounded, 10^3 = 1000.").verdict == NOT_APPLICABLE
    assert _v(SymbolicSolver(), "The rate is 3,5 * 2 = 7.").verdict == NOT_APPLICABLE


def test_symbolic_thousands_and_multiply_still_verified():
    # The fail-closed guards must not over-skip legitimate arithmetic.
    assert _v(SymbolicSolver(), "Sum: 1,000 + 2,000 = 3,000.").verdict == PASS
    assert _v(SymbolicSolver(), "Area is 2 x 3 = 6.").verdict == PASS
    assert _v(SymbolicSolver(), "Sum is 12 + 12 = 25.").verdict == FAIL


def test_hallucination_non_dollar_currency_is_checked():
    # A fabricated euro/pound amount must be caught, not silently uncheckable.
    assert _v(HallucinationDetector(), "The fee is €900.",
              sources=["The fee is €50 per item."]).verdict == FAIL
    assert _v(HallucinationDetector(), "It costs £500.",
              sources=["It costs £30."]).verdict == FAIL
    # ...and a grounded non-$ amount still passes.
    assert _v(HallucinationDetector(), "The fee is €50.",
              sources=["The fee is €50 per item."]).verdict == PASS


def test_hallucination_contradiction_is_a_documented_scope_limit():
    # Extractive grounding checks PRESENCE, not polarity: a negated specific whose
    # value still appears in the source is NOT caught extractively (by design).
    extractive = _v(HallucinationDetector(), "Refunds are NOT available within 30 days.",
                    sources=["Refunds are available within 30 days of purchase."])
    assert extractive.verdict == PASS  # the documented limit
    # The optional entailment hook is the layer that catches contradictions.
    caught = HallucinationDetector(entailment_fn=lambda ans, src: False).run(
        "Refunds are NOT available within 30 days.",
        VerificationContext(sources=["Refunds are available within 30 days of purchase."]))
    assert caught.verdict == FAIL


def test_schema_rejects_non_finite_numbers():
    # NaN / Infinity are the json stdlib's extension, not valid JSON, and must not
    # satisfy a {"type": "number"} schema (probe found them passing).
    schema = {"type": "object", "required": ["amount"], "properties": {"amount": {"type": "number"}}}
    assert _v(SchemaValidator(), '{"amount": NaN}', schema=schema).verdict == FAIL
    assert _v(SchemaValidator(), '{"amount": Infinity}', schema=schema).verdict == FAIL
    assert _v(SchemaValidator(), '{"amount": -Infinity}', schema=schema).verdict == FAIL
    assert _v(SchemaValidator(), '{"amount": 42}', schema=schema).verdict == PASS


def test_temporal_morphology_evasion_is_caught():
    # Plurals and hyphen variants must not evade the anachronism check.
    assert _v(TemporalConsistency(), "They wore smartwatches in 1850.").verdict == FAIL
    assert _v(TemporalConsistency(), "They drove cars in 1700.").verdict == FAIL
    assert _v(TemporalConsistency(), "She used a smart-watch in 1850.").verdict == FAIL


def test_temporal_plural_does_not_overfire():
    # The plural tolerance must stay word-safe: "cares"/"cards" are not "car".
    assert _v(TemporalConsistency(), "In 1850 she cares about the cards.").verdict == NOT_APPLICABLE
