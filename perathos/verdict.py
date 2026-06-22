"""Verdict Record (128) — the structured output of a single verifier module.

Per the VRL design, every verifier emits exactly one Verdict Record. We carry
the required fields (verifier id, verdict, detail, version) plus the fields that
make a verdict *auditable and reproducible* once it is bound into a signed proof
bundle:

  * method           — how the verdict was computed (e.g. "self-consistency").
  * confidence_bps   — calibrated confidence in basis points (0..1000). The
                       honest default is 0: "no stated confidence", never a
                       fabricated 100%.
  * evidence_digests — SHA-256 digests of the exact evidence the verdict was
                       computed over (samples compared, documents retrieved).
                       Binding digests — not raw evidence — keeps bundles small
                       and privacy-preserving while letting a downstream
                       consumer re-check the verdict against the same evidence.

A verdict is *evidence*, never a guarantee. INCONCLUSIVE is a first-class
outcome and means "not enough evidence to decide" — it must never be silently
promoted to PASS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_APPLICABLE = "NOT_APPLICABLE"

VALID_VERDICTS = {PASS, FAIL, WARN, INCONCLUSIVE, NOT_APPLICABLE}


@dataclass
class VerdictRecord:
    verifier_id: int
    verifier_name: str
    verifier_version: str
    verdict: str
    confidence_bps: int = 0
    method: str = ""
    detail: str = ""
    evidence_digests: List[str] = field(default_factory=list)
    # Optional RAW structured evidence (e.g. the recomputed equations, the
    # ungrounded specifics). evidence_digests always binds it; carrying the raw
    # form too enables audit/replay at the cost of size/privacy, so it is opt-in
    # (None by default) and can be redacted. Engines populate it; the lighter
    # verifiers leave it None (digest-only).
    evidence: Optional[dict] = None
    # True when an engine independently computed this verdict (the honest case —
    # perathos always runs the verifier). A future ingest path for a verdict the
    # model merely *asserted* about itself would set this False; only computed
    # verdicts count toward "independently verified".
    computed: bool = True

    def __post_init__(self) -> None:
        if self.verdict not in VALID_VERDICTS:
            raise ValueError(f"invalid verdict {self.verdict!r}; must be one of {sorted(VALID_VERDICTS)}")
        self.confidence_bps = max(0, min(1000, int(self.confidence_bps)))

    def to_dict(self) -> dict:
        # Keys are emitted in a fixed shape; canonical serialization sorts them
        # deterministically when the record is hashed into the proof bundle.
        return {
            "verifier_id": self.verifier_id,
            "verifier_name": self.verifier_name,
            "verifier_version": self.verifier_version,
            "verdict": self.verdict,
            "confidence_bps": self.confidence_bps,
            "method": self.method,
            "detail": self.detail,
            "evidence_digests": list(self.evidence_digests),
            "computed": bool(self.computed),
            **({"evidence": self.evidence} if self.evidence is not None else {}),
        }
