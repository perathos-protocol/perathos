"""Deterministic legal-citation extraction and normalization.

Pure-stdlib, no network, no model. Finds U.S. Reports citations (optionally with
the case name that precedes them) in free text and normalizes them to a canonical
form for resolution against a pinned corpus snapshot.

Honesty discipline (mirrors the other engines): prefer precise patterns over
greedy ones. An unrecognized string is *skipped*, never guessed at — a parser
miss must not become a false fabrication flag.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

# Bump when the grammar / normalization rules change; bound into the verdict so a
# verdict is reproducible only against the same rules + the same corpus snapshot.
RULES_VERSION = "citation-rules-1.0.0"

# Stopwords dropped when comparing case names, so a short form ("Brown v. Board")
# still overlaps the full name ("Brown v. Board of Education"). Party-name overlap
# is used only to FLAG a clearly-wrong name, so this set stays conservative.
_NAME_STOP = {"v", "vs", "of", "the", "co", "inc", "llc", "corp", "et", "al",
              "and", "in", "re", "ex", "rel", "a", "an"}

# Leading words that introduce a citation but are not part of the case name
# ("As held in Roe v. Wade", "In Brown v. Board", "See ..."). Stripped from a
# captured name. Safe because the name is only used to flag a CLEARLY-wrong name.
_LEADING_SIGNALS = {"as", "held", "in", "see", "per", "the", "cf", "accord",
                    "compare", "but", "and", "eg", "id", "citing", "quoting"}

# A party name: a capitalized word, then capitalized words optionally joined by a
# short run of lowercase connectors ("of the University of California"). Bounded
# segment count so it can't run away.
_CONN = r"(?:of|the|and|for|et|al|&)"
_PARTY = (r"[A-Z][A-Za-z.'’&-]*"
          r"(?:\s+(?:" + _CONN + r"\s+)*[A-Z][A-Za-z.'’&-]*){0,6}")
_CITE_RE = re.compile(
    r"(?:(?P<name>" + _PARTY + r"\s+v\.?\s+" + _PARTY + r")\s*,\s*)?"
    r"(?P<volume>\d{1,4})\s+(?P<reporter>U\.?\s?S\.?)\s+(?P<page>\d{1,4})"
    r"(?:\s*,\s*(?P<pin>\d{1,4}))?"
    r"(?:\s*\(\s*(?P<year>\d{4})\s*\))?",
)


def _strip_leading_signals(name: str) -> str:
    """Drop introductory words a name regex may have absorbed before the party."""
    words = name.split()
    while len(words) > 2 and words[0].strip(".,").lower() in _LEADING_SIGNALS:
        words = words[1:]
    return " ".join(words)

# A quoted string of reasonable length attributed near a citation.
_QUOTE_RE = re.compile(r"[\"“]([^\"“”]{8,400})[\"”]")


@dataclass
class Citation:
    """One parsed citation occurrence."""

    raw: str
    reporter: str               # normalized, e.g. "U.S."
    volume: int
    page: int
    name: Optional[str] = None  # case name as written, if present
    pin: Optional[int] = None   # pinpoint page
    year: Optional[int] = None
    start: int = 0
    end: int = 0


def normalize_reporter(raw: str) -> str:
    """Canonicalize a reporter token: 'U. S.', 'US', 'U.S.' -> 'U.S.'."""
    collapsed = re.sub(r"\s+", "", raw).upper()
    if collapsed in ("U.S.", "US", "U.S"):
        return "U.S."
    return raw.strip()


def name_tokens(name: Optional[str]) -> set:
    """Significant lowercase word tokens of a case name (stopwords removed).

    Used to decide whether a written name is *clearly* a different case from the
    one a citation resolves to. Returns an empty set for no/garbage name.
    """
    if not name:
        return set()
    words = re.findall(r"[A-Za-z]+", name.lower())
    return {w for w in words if w not in _NAME_STOP and len(w) > 1}


def parse_citations(text: str, *, limit: int = 200) -> List[Citation]:
    """Extract U.S. Reports citations (with optional case names) from text.

    Bounded work: scans at most `limit` matches and a length-capped input so a
    hostile document cannot cause unbounded work.
    """
    text = text[:200_000]
    out: List[Citation] = []
    for m in _CITE_RE.finditer(text):
        if len(out) >= limit:
            break
        try:
            volume = int(m.group("volume"))
            page = int(m.group("page"))
        except (TypeError, ValueError):
            continue
        pin = int(m.group("pin")) if m.group("pin") else None
        year = int(m.group("year")) if m.group("year") else None
        name = m.group("name")
        clean_name = _strip_leading_signals(name.strip()) if name else None
        out.append(Citation(
            raw=m.group(0).strip(),
            reporter=normalize_reporter(m.group("reporter")),
            volume=volume,
            page=page,
            name=clean_name,
            pin=pin,
            year=year,
            start=m.start(),
            end=m.end(),
        ))
    return out


def quotes_near(text: str, start: int, end: int, *, window: int = 240) -> List[str]:
    """Quoted strings appearing just before/after a citation span — candidate
    text the output attributes to that authority."""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    return [q.group(1).strip() for q in _QUOTE_RE.finditer(text[lo:hi])]
