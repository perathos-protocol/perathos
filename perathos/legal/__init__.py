"""perathos.legal — domain verifiers for legal text.

M0: the Legal Citation Verifier (engine 128) — deterministically check that the
U.S. case-law citations in an AI output exist and are attributed to the right
case, against a pinned, content-addressed public snapshot. Pure stdlib; no
network at verify time. See docs/specs/CITATION_VERIFIER.md.
"""
from .citations import Citation, parse_citations
from .corpus import CaseRecord, CitationCorpus, load_default_corpus
from .engine import CitationVerifier

__all__ = [
    "Citation",
    "parse_citations",
    "CaseRecord",
    "CitationCorpus",
    "load_default_corpus",
    "CitationVerifier",
]
