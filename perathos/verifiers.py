"""Content verifiers that produce auditable hallucination signals.

These populate the multi-verifier pipeline whose verdicts are bound into a
signed proof bundle. Two reference verifiers are provided:

  * CrossExaminer (122) — self-consistency. Compares the primary output against
    additional samples drawn from the same model for the same prompt; wide
    disagreement across samples is a hallucination signal (cf. SelfCheckGPT).
  * ClaimEntailmentVerifier (124) — retrieval + claim-level entailment. Splits
    the output into atomic claims and labels each supported / contradicted /
    unverifiable against supplied evidence (cf. FActScore / SAFE).

HONESTY: the default similarity and entailment functions are deterministic
LEXICAL placeholders so the pipeline runs and is testable fully offline. They
are NOT semantic models. Inject a real embedding / NLI / LLM function via the
constructor for production use. The verifiers emit *evidence*, never a guarantee.

ROBUSTNESS: a verifier must never crash the pipeline or default to PASS on
failure. The base Verifier.run() wraps verification so any exception — and any
verifier given no evidence to work from — yields INCONCLUSIVE, not PASS.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .verdict import (
    FAIL,
    INCONCLUSIVE,
    PASS,
    WARN,
    VerdictRecord,
)


def evidence_digest(text: str) -> str:
    """Namespaced SHA-256 digest of an evidence string (sample or document)."""
    return "sha-256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class VerificationContext:
    """Everything a verifier may consult about an output under verification."""

    # Additional samples drawn from the same model for the same prompt
    # (for self-consistency). Each is compared against the primary output.
    samples: List[str] = field(default_factory=list)
    # Trusted evidence documents (for retrieval-entailment claim checking).
    evidence: List[str] = field(default_factory=list)
    # Grounding sources for the extractive HallucinationDetector engine.
    sources: List[str] = field(default_factory=list)
    # Declared JSON Schema for the SchemaValidator engine.
    schema: Optional[dict] = None
    # Optional term -> earliest-year overrides for the TemporalConsistency engine.
    timeline: Optional[dict] = None


# ── similarity / entailment plug points (deterministic lexical defaults) ───────

def _tokens(s: str) -> set:
    return set(re.findall(r"\w+", s.lower()))


def lexical_jaccard(a: str, b: str) -> float:
    """Token Jaccard similarity in [0, 1]. A cheap, deterministic stand-in for a
    semantic similarity model — replace with embeddings for production."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


SUPPORTED = "supported"
CONTRADICTED = "contradicted"
UNVERIFIABLE = "unverifiable"


def lexical_entailment(claim: str, evidence: List[str]) -> str:
    """Deterministic placeholder entailment: label a claim SUPPORTED if its
    tokens are largely covered by some evidence document, else UNVERIFIABLE.

    Deliberately NEVER returns CONTRADICTED: lexical overlap cannot reliably
    detect contradiction, and a false CONTRADICTED would wrongly FAIL an output.
    Inject a real NLI/LLM entailment function to get contradiction detection.
    """
    ct = _tokens(claim)
    if not ct:
        return UNVERIFIABLE
    best = 0.0
    for doc in evidence:
        dt = _tokens(doc)
        best = max(best, len(ct & dt) / len(ct))
    return SUPPORTED if best >= 0.6 else UNVERIFIABLE


def split_claims(output: str) -> List[str]:
    """Naive atomic-claim decomposition by sentence boundary. A real system
    would use a claim extractor; this is a deterministic stand-in."""
    parts = re.split(r"(?<=[.!?])\s+", output.strip())
    return [p.strip() for p in parts if p.strip()]


# ── verifier base ──────────────────────────────────────────────────────────────

class Verifier:
    verifier_id: int = 0
    verifier_name: str = "Verifier"
    verifier_version: str = "0.1.0"
    method: str = ""

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:  # pragma: no cover
        raise NotImplementedError

    def run(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        """Run the verifier with a safety net: any exception becomes an
        INCONCLUSIVE verdict (confidence 0), never a crash and never a PASS."""
        try:
            return self._verify(output, ctx)
        except Exception as exc:  # robustness: degrade to INCONCLUSIVE, never PASS
            return VerdictRecord(
                verifier_id=self.verifier_id,
                verifier_name=self.verifier_name,
                verifier_version=self.verifier_version,
                verdict=INCONCLUSIVE,
                confidence_bps=0,
                method=self.method,
                detail=f"verifier error: {type(exc).__name__}: {exc}",
                evidence_digests=[],
            )

    def _record(self, verdict, confidence_bps, detail, evidence_digests=None) -> VerdictRecord:
        return VerdictRecord(
            verifier_id=self.verifier_id,
            verifier_name=self.verifier_name,
            verifier_version=self.verifier_version,
            verdict=verdict,
            confidence_bps=confidence_bps,
            method=self.method,
            detail=detail,
            evidence_digests=evidence_digests or [],
        )


# ── 122 Cross-Examiner (self-consistency) ──────────────────────────────────────

class CrossExaminer(Verifier):
    verifier_id = 122
    verifier_name = "Cross-Examiner"
    verifier_version = "0.1.0"
    method = "self-consistency/lexical-agreement"

    def __init__(
        self,
        similarity_fn: Optional[Callable[[str, str], float]] = None,
        pass_threshold: float = 0.6,
        fail_threshold: float = 0.3,
    ):
        self.similarity_fn = similarity_fn or lexical_jaccard
        self.pass_threshold = pass_threshold
        self.fail_threshold = fail_threshold

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        samples = list(ctx.samples or [])
        if not samples:
            return self._record(INCONCLUSIVE, 0, "no resamples provided; cannot assess self-consistency")
        sims = [float(self.similarity_fn(output, s)) for s in samples]
        agreement = sum(sims) / len(sims)
        digests = [evidence_digest(s) for s in samples]
        # Confidence = decisiveness: how far agreement sits from the ambiguous
        # midpoint (0.5). High agreement OR high disagreement is a confident
        # signal; a middling score is not.
        confidence_bps = int(min(1.0, abs(agreement - 0.5) * 2) * 1000)
        detail = f"{len(samples)} resamples, mean agreement {agreement:.2f}"
        if agreement >= self.pass_threshold:
            return self._record(PASS, confidence_bps, f"stable: {detail}", digests)
        if agreement <= self.fail_threshold:
            return self._record(FAIL, confidence_bps, f"unstable (likely hallucination): {detail}", digests)
        return self._record(WARN, confidence_bps, f"partially unstable: {detail}", digests)


# ── 124 Claim-Entailment Verifier (retrieval + claim decomposition) ────────────

class ClaimEntailmentVerifier(Verifier):
    verifier_id = 124
    verifier_name = "Claim-Entailment Verifier"
    verifier_version = "0.1.0"
    method = "retrieval-entailment/claim-decomposition"

    def __init__(self, entailment_fn: Optional[Callable[[str, List[str]], str]] = None):
        self.entailment_fn = entailment_fn or lexical_entailment

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        evidence = list(ctx.evidence or [])
        if not evidence:
            return self._record(INCONCLUSIVE, 0, "no evidence provided; cannot assess factual support")
        claims = split_claims(output)
        if not claims:
            return self._record(INCONCLUSIVE, 0, "no checkable claims extracted from output")
        digests = [evidence_digest(d) for d in evidence]
        labels = [self.entailment_fn(c, evidence) for c in claims]
        n = len(labels)
        supported = labels.count(SUPPORTED)
        contradicted = labels.count(CONTRADICTED)
        unverifiable = labels.count(UNVERIFIABLE)
        detail = f"{supported}/{n} supported, {contradicted} contradicted, {unverifiable} unverifiable"
        if contradicted > 0:
            return self._record(FAIL, int(contradicted / n * 1000), f"contradicted by evidence: {detail}", digests)
        if unverifiable == 0:
            return self._record(PASS, int(supported / n * 1000), f"fully supported: {detail}", digests)
        # Some claims lack evidence — abstain rather than over-claim support.
        return self._record(INCONCLUSIVE, int(unverifiable / n * 1000), f"not enough evidence: {detail}", digests)


def default_verifiers() -> List[Verifier]:
    """The standard reference pipeline: self-consistency + claim entailment."""
    return [CrossExaminer(), ClaimEntailmentVerifier()]
