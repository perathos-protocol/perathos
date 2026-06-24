"""Legal Citation Verifier — engine 128.

Deterministically checks that the legal authorities an AI output cites actually
exist (in a pinned snapshot) and are attributed to the right case. Verdicts are
honesty-first: it FAILs only on positive fabrication evidence, and reports
INCONCLUSIVE — never a false FAIL — when a cite is simply outside the snapshot's
coverage. See docs/specs/CITATION_VERIFIER.md.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional

from ..canonical import canonical_bytes
from ..verdict import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, VerdictRecord
from ..verifiers import VerificationContext, Verifier
from .citations import RULES_VERSION, name_tokens, parse_citations, quotes_near
from .corpus import CitationCorpus


def _digest(obj) -> str:
    return "sha-256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


# Per-citation outcomes (worst-first for aggregation).
_FABRICATED = "fabricated"        # impossible cite for a known reporter -> FAIL
_MISATTRIBUTED = "misattributed"  # cite resolves, but the written name is wrong -> FAIL
_GROUNDED = "grounded"            # resolves, name consistent -> PASS-eligible
_OUT_OF_COVERAGE = "out_of_coverage"  # plausible, not in snapshot -> INCONCLUSIVE


class CitationVerifier(Verifier):
    verifier_id = 128
    verifier_name = "Legal Citation Verifier"
    verifier_version = "1.0.0"
    method = "computed:citation-resolution"

    def __init__(self, corpus: Optional[CitationCorpus] = None) -> None:
        # Default to the bundled snapshot; loading is lazy-safe (any failure
        # degrades to NOT_APPLICABLE rather than crashing the pipeline).
        self._corpus = corpus
        self._corpus_error: Optional[str] = None
        if corpus is None:
            try:
                self._corpus = CitationCorpus.load_default()
            except Exception as exc:  # no snapshot available -> NOT_APPLICABLE
                self._corpus_error = f"{type(exc).__name__}: {exc}"

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        corpus = self._corpus
        if corpus is None:
            return self._record(NOT_APPLICABLE, 0,
                                f"no citation corpus configured ({self._corpus_error})")

        text = output if isinstance(output, str) else str(output)
        cites = parse_citations(text)
        if not cites:
            return self._record(NOT_APPLICABLE, 0, "no legal citations found in the output")

        findings: List[dict] = []
        for c in cites:
            entry = {"raw": c.raw, "reporter": c.reporter, "volume": c.volume,
                     "page": c.page, "name": c.name}
            if not corpus.known_reporter(c.reporter):
                entry["status"] = _OUT_OF_COVERAGE
                entry["reason"] = "reporter not in snapshot coverage"
            elif corpus.structurally_impossible(c):
                info = corpus.reporter_info(c.reporter)
                entry["status"] = _FABRICATED
                entry["reason"] = (f"volume {c.volume} is outside {c.reporter} "
                                   f"(<= {info.max_volume}) as of snapshot {corpus.version}")
            else:
                rec = corpus.resolve(c)
                if rec is None:
                    entry["status"] = _OUT_OF_COVERAGE
                    entry["reason"] = "not in snapshot; existence cannot be confirmed or denied"
                else:
                    entry["resolved_name"] = rec.name
                    written = name_tokens(c.name)
                    # FAIL only on a CLEAR mismatch: a written name that shares no
                    # significant word with the true case name (a real cite stapled
                    # to a wrong/invented name). No name, or any overlap -> safe.
                    if written and not (written & name_tokens(rec.name)):
                        entry["status"] = _MISATTRIBUTED
                        entry["reason"] = f"cite resolves to {rec.name!r}, not the written name"
                    else:
                        entry["status"] = _GROUNDED
                        q = self._matched_quote(text, c, rec, corpus)
                        if q:
                            entry["grounded_quote"] = q
            findings.append(entry)

        return self._aggregate(findings, corpus)

    def _matched_quote(self, text, cite, rec, corpus) -> Optional[str]:
        """A bonus PASS signal: a quoted string near the cite that matches a
        stored verbatim quote for that case. (Absence is NOT a failure in M0 —
        the snapshot holds notable quotes, not full opinion text.)"""
        stored = corpus.quotes_for(rec)
        if not stored:
            return None
        norm = {self._norm(s): s for s in stored}
        for cand in quotes_near(text, cite.start, cite.end):
            if self._norm(cand) in norm:
                return norm[self._norm(cand)]
        return None

    @staticmethod
    def _norm(s: str) -> str:
        return " ".join(s.lower().split())

    def _aggregate(self, findings: List[dict], corpus: CitationCorpus) -> VerdictRecord:
        evidence = {
            "corpus_version": corpus.version,
            "corpus_hash": corpus.content_hash,
            "engine_rules_version": RULES_VERSION,
            "citations": findings,
        }
        digests = [_digest(evidence)]
        statuses = [f["status"] for f in findings]
        n = len(findings)
        bad = [f for f in findings if f["status"] in (_FABRICATED, _MISATTRIBUTED)]
        grounded = sum(1 for s in statuses if s == _GROUNDED)
        uncov = sum(1 for s in statuses if s == _OUT_OF_COVERAGE)

        if bad:
            b = bad[0]
            return self._record(
                FAIL, 1000,
                f"{len(bad)} of {n} citation(s) do not check out, e.g. {b['raw']!r}: {b['reason']}",
                digests, evidence)
        if grounded and not uncov:
            return self._record(
                PASS, 700,
                f"all {n} citation(s) resolve in snapshot {corpus.version} with consistent names",
                digests, evidence)
        # Some (or all) cites are outside coverage and none are fabricated: we
        # could not fully verify. Abstain rather than over-claim either way.
        return self._record(
            INCONCLUSIVE, 300,
            f"{grounded}/{n} grounded, {uncov}/{n} outside snapshot coverage; cannot fully verify",
            digests, evidence)

    def _record(self, verdict, confidence_bps, detail, evidence_digests=None, evidence=None):
        return VerdictRecord(
            verifier_id=self.verifier_id,
            verifier_name=self.verifier_name,
            verifier_version=self.verifier_version,
            verdict=verdict,
            confidence_bps=confidence_bps,
            method=self.method,
            detail=detail,
            evidence_digests=evidence_digests or [],
            evidence=evidence,
        )
