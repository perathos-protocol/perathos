"""Tests for the content verifiers and the multi-verifier pipeline."""
from perathos.pipeline import CONJUNCTION, MultiVerifierPipeline
from perathos.verdict import FAIL, INCONCLUSIVE, PASS, WARN
from perathos.verifiers import (
    ClaimEntailmentVerifier,
    CrossExaminer,
    VerificationContext,
    evidence_digest,
)


# ── Cross-Examiner (self-consistency) ─────────────────────────────────────────

def test_cross_examiner_inconclusive_without_samples():
    rec = CrossExaminer().run("The capital of France is Paris.", VerificationContext())
    assert rec.verdict == INCONCLUSIVE
    assert rec.confidence_bps == 0
    assert rec.evidence_digests == []


def test_cross_examiner_passes_on_stable_samples():
    out = "The capital of France is Paris."
    ctx = VerificationContext(samples=[out, "Paris is the capital of France.", out])
    rec = CrossExaminer().run(out, ctx)
    assert rec.verdict in (PASS, WARN)
    # evidence digests bind exactly which samples were compared
    assert rec.evidence_digests == [evidence_digest(s) for s in ctx.samples]


def test_cross_examiner_fails_on_divergent_samples():
    out = "The capital of France is Paris."
    ctx = VerificationContext(samples=["bananas grow underwater", "the moon is cheese", "xyzzy"])
    rec = CrossExaminer().run(out, ctx)
    assert rec.verdict == FAIL


def test_cross_examiner_is_inconclusive_not_crash_on_bad_similarity_fn():
    def boom(a, b):
        raise RuntimeError("model down")
    rec = CrossExaminer(similarity_fn=boom).run("x", VerificationContext(samples=["y"]))
    assert rec.verdict == INCONCLUSIVE  # robustness: never crash, never PASS
    assert "model down" in rec.detail


# ── Claim-Entailment Verifier ─────────────────────────────────────────────────

def test_entailment_inconclusive_without_evidence():
    rec = ClaimEntailmentVerifier().run("The Eiffel Tower is in Paris.", VerificationContext())
    assert rec.verdict == INCONCLUSIVE


def test_entailment_passes_when_claims_supported():
    out = "The Eiffel Tower is in Paris."
    ctx = VerificationContext(evidence=["The Eiffel Tower is a landmark located in Paris, France."])
    rec = ClaimEntailmentVerifier().run(out, ctx)
    assert rec.verdict == PASS
    assert rec.evidence_digests == [evidence_digest(ctx.evidence[0])]


def test_entailment_abstains_on_unsupported_claim():
    out = "The Eiffel Tower is in Paris. It was built by aliens in 3000 BC."
    ctx = VerificationContext(evidence=["The Eiffel Tower is a landmark located in Paris, France."])
    rec = ClaimEntailmentVerifier().run(out, ctx)
    # second claim is unverifiable -> abstain, NOT pass
    assert rec.verdict == INCONCLUSIVE


def test_entailment_fails_on_injected_contradiction_fn():
    def contradicts(claim, evidence):
        return "contradicted"
    rec = ClaimEntailmentVerifier(entailment_fn=contradicts).run(
        "Some claim.", VerificationContext(evidence=["doc"])
    )
    assert rec.verdict == FAIL


# ── Pipeline aggregation ──────────────────────────────────────────────────────

def test_pipeline_conjunction_fail_dominates():
    out = "The capital of France is Paris."
    ctx = VerificationContext(
        samples=["nonsense alpha", "nonsense beta", "nonsense gamma"],  # -> FAIL
        evidence=["The capital of France is Paris."],                    # -> PASS
    )
    result = MultiVerifierPipeline(mode=CONJUNCTION).run(out, ctx)
    assert result.aggregate["verdict"] == FAIL
    assert result.aggregate["fail_count"] == 1
    assert len(result.records) == 2


def test_pipeline_inconclusive_when_nothing_decides():
    result = MultiVerifierPipeline().run("anything", VerificationContext())
    assert result.aggregate["verdict"] == INCONCLUSIVE
    assert result.aggregate["inconclusive_count"] == 2
    assert result.aggregate["applicable_count"] == 0


def test_pipeline_all_pass():
    out = "The capital of France is Paris."
    ctx = VerificationContext(
        samples=[out, out],
        evidence=["The capital of France is Paris."],
    )
    result = MultiVerifierPipeline(mode=CONJUNCTION).run(out, ctx)
    assert result.aggregate["verdict"] == PASS


def test_block_serialization_is_canonical_shaped():
    result = MultiVerifierPipeline().run("x", VerificationContext(samples=["x"]))
    block = result.to_block()
    assert block["schema"] == "vrl/verification/1"
    assert "aggregate" in block
    assert isinstance(block["verdict_records"], list)


def test_unknown_mode_rejected():
    try:
        MultiVerifierPipeline(mode="bogus")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "bogus" in str(exc)
