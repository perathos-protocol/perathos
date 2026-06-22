"""Multi-Verifier Pipeline (120) and aggregate-verdict computation.

Runs the verifier modules against an output, collects their Verdict Records, and
derives a single aggregate verdict. Three aggregation modes are supported:

  * conjunction — any FAIL fails the aggregate; else any WARN warns; else PASS
                  (strictest; the default for a proof layer).
  * quorum      — a majority of *applicable* verifiers must PASS.
  * weighted    — reserved; currently behaves like quorum on equal weights.

INCONCLUSIVE and NOT_APPLICABLE are excluded from the PASS/FAIL denominator: a
verifier that could not decide must not be counted as agreement. The whole
result serializes to a `verification` block that is hashed into the proof
bundle's integrity hash, so the verdicts are tamper-evident and signed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .verdict import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, WARN, VerdictRecord
from .verifiers import VerificationContext, Verifier, default_verifiers

CONJUNCTION = "conjunction"
QUORUM = "quorum"
WEIGHTED = "weighted"

VERIFICATION_SCHEMA = "vrl/verification/1"


@dataclass
class VerificationResult:
    aggregate: dict
    records: List[VerdictRecord]

    def to_block(self) -> dict:
        """The signed, tamper-evident verification block stored in the bundle."""
        return {
            "schema": VERIFICATION_SCHEMA,
            "aggregate": self.aggregate,
            "verdict_records": [r.to_dict() for r in self.records],
        }


class MultiVerifierPipeline:
    def __init__(self, verifiers: Optional[List[Verifier]] = None, mode: str = CONJUNCTION):
        if mode not in (CONJUNCTION, QUORUM, WEIGHTED):
            raise ValueError(f"unknown aggregation mode {mode!r}")
        verifiers = verifiers if verifiers is not None else default_verifiers()
        for v in verifiers:
            if not callable(getattr(v, "run", None)):
                raise TypeError(
                    f"each item in `verifiers` must expose a callable .run(); got {type(v).__name__}. "
                    "Did you pass input_text positionally? verify_output's signature is "
                    "verify_output(output_text, input_text='', *, verifiers=..., context=...)."
                )
        self.verifiers = verifiers
        self.mode = mode

    def run(self, output: str, ctx: VerificationContext) -> VerificationResult:
        records = [v.run(output, ctx) for v in self.verifiers]
        records.sort(key=lambda r: r.verifier_id)
        return VerificationResult(self._aggregate(records), records)

    def _aggregate(self, records: List[VerdictRecord]) -> dict:
        applicable = [r for r in records if r.verdict not in (NOT_APPLICABLE, INCONCLUSIVE)]
        passes = [r for r in applicable if r.verdict == PASS]
        fails = [r for r in applicable if r.verdict == FAIL]
        warns = [r for r in applicable if r.verdict == WARN]
        inconclusive = [r for r in records if r.verdict == INCONCLUSIVE]
        n = len(applicable)

        if n == 0:
            verdict, rationale = INCONCLUSIVE, "no verifier could decide"
        elif self.mode == CONJUNCTION:
            if fails:
                verdict, rationale = FAIL, f"{len(fails)} verifier(s) failed"
            elif warns:
                verdict, rationale = WARN, f"{len(warns)} verifier(s) warned"
            else:
                verdict, rationale = PASS, "all deciding verifiers passed"
        else:  # QUORUM / WEIGHTED (equal weights)
            if fails:
                verdict, rationale = FAIL, f"{len(fails)} verifier(s) failed"
            elif len(passes) * 2 > n:
                verdict = WARN if warns else PASS
                rationale = f"{len(passes)}/{n} passed (quorum met)"
            else:
                verdict, rationale = WARN, f"only {len(passes)}/{n} passed (no quorum)"

        # Aggregate confidence is the MINIMUM confidence among the records that
        # drove the verdict — the chain is only as strong as its weakest link.
        drivers = fails if fails else (warns if (warns and verdict == WARN) else passes)
        confidence_bps = min((r.confidence_bps for r in drivers), default=0)

        return {
            "verdict": verdict,
            "mode": self.mode,
            "rationale": rationale,
            "confidence_bps": confidence_bps,
            "pass_count": len(passes),
            "fail_count": len(fails),
            "warn_count": len(warns),
            "inconclusive_count": len(inconclusive),
            "not_applicable_count": sum(1 for r in records if r.verdict == NOT_APPLICABLE),
            "applicable_count": n,
            "total_count": len(records),
        }


def verify_output(
    output_text: str,
    input_text: str = "",
    *,
    verifiers: Optional[List[Verifier]] = None,
    context: Optional[VerificationContext] = None,
    mode: str = CONJUNCTION,
    model: str = "unspecified",
    include_answer: bool = False,
) -> dict:
    """Run the verifier pipeline over an output and return a proof bundle whose
    integrity hash binds the resulting verdicts.

    The bundle can then be signed with sign()/sign_bundle() and verified offline;
    any tampering with a verdict record breaks the integrity hash.
    """
    from .bundle import create_bundle  # local import avoids an import cycle

    ctx = context if context is not None else VerificationContext()
    result = MultiVerifierPipeline(verifiers, mode).run(output_text, ctx)
    return create_bundle(output_text, input_text=input_text, verification=result.to_block(),
                         model=model, include_answer=include_answer)
