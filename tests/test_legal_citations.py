"""Tests for the Legal Citation Verifier (engine 128) — M0.

The cardinal rule, as everywhere in perathos: NEVER false-flag. A real,
in-coverage citation must verify; an out-of-coverage cite is INCONCLUSIVE, never
FAIL. We only FAIL on positive fabrication evidence.
"""
import pytest

from perathos.verdict import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS
from perathos.verifiers import VerificationContext
from perathos.legal import CitationVerifier, load_default_corpus, parse_citations


def _v(text):
    return CitationVerifier().run(text, VerificationContext())


# ── parser ────────────────────────────────────────────────────────────────────

def test_parser_extracts_name_and_cite():
    cites = parse_citations("As held in Roe v. Wade, 410 U.S. 113 (1973), the right...")
    assert len(cites) == 1
    c = cites[0]
    assert (c.volume, c.reporter, c.page, c.year) == (410, "U.S.", 113, 1973)
    assert c.name == "Roe v. Wade"


def test_parser_handles_bare_cite_and_normalizes_reporter():
    cites = parse_citations("see 347 U. S. 483 and 384 US 436")
    assert {(c.volume, c.page) for c in cites} == {(347, 483), (384, 436)}
    assert all(c.reporter == "U.S." for c in cites)
    assert all(c.name is None for c in cites)


# ── grounded (PASS) ─────────────────────────────────────────────────────────────

def test_real_citation_passes():
    r = _v("The Court in Brown v. Board of Education, 347 U.S. 483 (1954), held...")
    assert r.verdict == PASS
    assert r.evidence["corpus_hash"].startswith("sha-256:")


def test_short_form_name_still_passes():
    # "Brown v. Board" shares a party word with "Brown v. Board of Education" ->
    # must NOT be flagged as a mismatch.
    assert _v("See Brown v. Board, 347 U.S. 483.").verdict == PASS


def test_bare_real_cite_passes():
    assert _v("see 410 U.S. 113").verdict == PASS


def test_matched_quote_is_recorded():
    r = _v('Marbury v. Madison, 5 U.S. 137, said it is "It is emphatically the '
            'province and duty of the judicial department to say what the law is."')
    assert r.verdict == PASS
    assert any("grounded_quote" in c for c in r.evidence["citations"])


# ── fabrication (FAIL) ──────────────────────────────────────────────────────────

def test_impossible_volume_fails():
    # Vol 999 of U.S. Reports does not exist as of the snapshot -> fabrication.
    r = _v("As stated in United States v. Smith, 999 U.S. 1234 (2021)...")
    assert r.verdict == FAIL
    assert "999" in r.detail


def test_misattributed_name_fails():
    # 410 U.S. 113 is Roe v. Wade; a wholly different name on that cite is the
    # classic hallucination pattern.
    r = _v("Per Henderson v. Calloway, 410 U.S. 113, the rule is...")
    assert r.verdict == FAIL
    assert "resolves" in r.detail.lower() or "not the written name" in str(r.evidence)


# ── honesty: out of coverage is INCONCLUSIVE, never FAIL ────────────────────────

def test_out_of_coverage_is_inconclusive_not_fail():
    # A plausible U.S. cite we simply don't have in the landmark snapshot. We must
    # NOT claim it is fabricated.
    r = _v("See Doe v. Roe, 415 U.S. 200 (1974).")
    assert r.verdict == INCONCLUSIVE


def test_unknown_reporter_is_inconclusive():
    # F.3d is a real reporter we don't cover in M0 -> out of coverage, not FAIL.
    r = _v("See Varghese v. China Southern Airlines, 925 F.3d 1339 (11th Cir. 2019).")
    assert r.verdict in (INCONCLUSIVE, NOT_APPLICABLE)


def test_no_citations_is_not_applicable():
    assert _v("This paragraph contains no legal citations at all.").verdict == NOT_APPLICABLE


# ── the cardinal red-team: FP must be ZERO on real, in-coverage cites ───────────

_REAL = [
    "Marbury v. Madison, 5 U.S. 137 (1803)",
    "Brown v. Board of Education, 347 U.S. 483 (1954)",
    "Gideon v. Wainwright, 372 U.S. 335 (1963)",
    "Miranda v. Arizona, 384 U.S. 436 (1966)",
    "Roe v. Wade, 410 U.S. 113 (1973)",
    "Obergefell v. Hodges, 576 U.S. 644 (2015)",
    "see 558 U.S. 310",  # Citizens United, bare cite
]

_FABRICATED = [
    "United States v. Smith, 999 U.S. 1234",      # impossible volume
    "Jones v. Acme Corp., 1500 U.S. 1 (2009)",    # impossible volume
    "Henderson v. Calloway, 410 U.S. 113",         # wrong name on Roe's cite
    "Fictional v. Imaginary, 347 U.S. 483",        # wrong name on Brown's cite
]


@pytest.mark.parametrize("text", _REAL)
def test_redteam_no_false_positive_on_real(text):
    assert _v(text).verdict != FAIL, f"false-flagged a real citation: {text!r}"


@pytest.mark.parametrize("text", _FABRICATED)
def test_redteam_catches_fabrications(text):
    assert _v(text).verdict == FAIL, f"missed a fabrication: {text!r}"


def test_corpus_hash_is_stable_and_reproducible():
    a = load_default_corpus()
    b = load_default_corpus()
    assert a.content_hash == b.content_hash  # deterministic, pinned
    assert a.content_hash.startswith("sha-256:")
