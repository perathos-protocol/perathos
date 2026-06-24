"""The pinned, content-addressed reference corpus for citation resolution.

The whole design rests on one rule: **no network at verify time.** Resolution is
a pure function of (citation, snapshot). The snapshot is immutable and
content-addressed; its hash is bound into the verdict so a third party who pins
the same snapshot recomputes a bit-identical result, and a verdict made against a
different/forged corpus is detectable.

The underlying data (U.S. case law) is PUBLIC — the defensibility is the
maintained, normalized, reproducibly-snapshotted index, not secret bytes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from importlib import resources
from typing import Dict, List, Optional, Tuple

from ..canonical import canonical_bytes
from .citations import Citation

_DEFAULT_SNAPSHOT = "scotus_landmark_v1.json"


@dataclass(frozen=True)
class CaseRecord:
    name: str
    reporter: str
    volume: int
    page: int
    year: Optional[int]
    quotes: Tuple[str, ...]


@dataclass(frozen=True)
class ReporterInfo:
    name: str
    indexed: bool
    max_volume: int
    complete_volumes: Tuple[Tuple[int, int], ...] = ()


class CitationCorpus:
    """An immutable, content-addressed snapshot of legal authorities.

    Build via `from_manifest` / `load_default`. `content_hash` is computed from
    the canonicalized manifest, so it is verifiable and reproducible — not a value
    we are merely trusted to report.
    """

    def __init__(self, manifest: dict) -> None:
        if not isinstance(manifest, dict):
            raise ValueError("corpus manifest must be a JSON object")
        self.version: str = str(manifest.get("version", "unversioned"))
        # The hash binds exactly what resolution depends on: the reporter table
        # and the case index (not the human-readable description).
        bound = {"version": self.version,
                 "reporters": manifest.get("reporters", {}),
                 "cases": manifest.get("cases", [])}
        self.content_hash: str = "sha-256:" + hashlib.sha256(canonical_bytes(bound)).hexdigest()

        self._reporters: Dict[str, ReporterInfo] = {}
        for rep, info in (manifest.get("reporters") or {}).items():
            ranges = tuple((int(lo), int(hi)) for lo, hi in info.get("complete_volumes", []))
            self._reporters[rep] = ReporterInfo(
                name=str(info.get("name", rep)),
                indexed=bool(info.get("indexed", False)),
                max_volume=int(info.get("max_volume", 0)),
                complete_volumes=ranges,
            )

        self._index: Dict[Tuple[str, int, int], CaseRecord] = {}
        for c in (manifest.get("cases") or []):
            rec = CaseRecord(
                name=str(c["name"]),
                reporter=str(c["reporter"]),
                volume=int(c["volume"]),
                page=int(c["page"]),
                year=int(c["year"]) if c.get("year") is not None else None,
                quotes=tuple(c.get("quotes", []) or ()),
            )
            self._index[(rec.reporter, rec.volume, rec.page)] = rec

    # ── resolution surface used by the engine ─────────────────────────────────

    def known_reporter(self, reporter: str) -> bool:
        return reporter in self._reporters

    def reporter_info(self, reporter: str) -> Optional[ReporterInfo]:
        return self._reporters.get(reporter)

    def resolve(self, cite: Citation) -> Optional[CaseRecord]:
        return self._index.get((cite.reporter, cite.volume, cite.page))

    def structurally_impossible(self, cite: Citation) -> bool:
        """True if the cite cannot be real for a KNOWN reporter as of this
        snapshot (non-positive volume/page, or volume above the reporter's
        published range). Fires for any KNOWN reporter with a declared range
        (indexed or not), so a fabricated out-of-range federal cite is caught;
        never fires for an unknown reporter, so it can't false-flag one."""
        info = self._reporters.get(cite.reporter)
        if info is None:
            return False
        if cite.volume < 1 or cite.page < 1:
            return True
        return info.max_volume > 0 and cite.volume > info.max_volume

    def is_completely_covered(self, cite: Citation) -> bool:
        """True if this snapshot claims COMPLETE coverage of the cite's volume —
        i.e. if the case were real we would hold it. A non-resolving cite in a
        complete range is therefore a fabrication, not merely out of coverage.
        Empty by default (a curated snapshot makes no completeness claim)."""
        info = self._reporters.get(cite.reporter)
        if info is None:
            return False
        return any(lo <= cite.volume <= hi for lo, hi in info.complete_volumes)

    def quotes_for(self, rec: CaseRecord) -> List[str]:
        return list(rec.quotes)

    # ── construction ──────────────────────────────────────────────────────────

    @classmethod
    def from_manifest(cls, manifest: dict) -> "CitationCorpus":
        return cls(manifest)

    @classmethod
    def load_default(cls) -> "CitationCorpus":
        """Load the bundled SCOTUS landmark snapshot shipped in the package."""
        with resources.files(__package__).joinpath("data", _DEFAULT_SNAPSHOT).open(
            "r", encoding="utf-8"
        ) as fh:
            return cls(json.load(fh))


def load_default_corpus() -> CitationCorpus:
    return CitationCorpus.load_default()
