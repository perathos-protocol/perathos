"""Claude Code Stop-hook integration.

Grounds an agent's final turn summary against what actually happened in the
session -- the tool outputs recorded in its transcript -- using the same
real, deterministic engines (`hallucination_detector`, `symbolic_solver`) the
rest of Perathos uses, then writes a signed Proof Bundle receipt.

Scope, stated plainly (see the `perathos hooks stop-check` docstring in cli.py
for the same claim in user-facing form): this catches a specific claim -- a
number, a quoted status, a named file -- that has no support anywhere in the
session's own tool outputs. It does NOT catch a claim that IS grounded but
still misrepresents the bigger picture, and it never blocks the agent; it
only records what it found. "Grounds the summary against what actually
happened," never "catches the agent lying."
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .engines import HallucinationDetector, SymbolicSolver
from .pipeline import verify_output
from .verifiers import VerificationContext

# Sources this large would blow past most models' useful grounding window
# for no benefit; a claim grounded in output beyond this is still ungrounded
# from the engine's point of view, which is honest -- it never silently
# passes because the source list was merely large.
_MAX_SOURCE_CHARS = 20_000


def extract_transcript_sources(transcript_path: str, *, max_chars: int = _MAX_SOURCE_CHARS) -> list[str]:
    """Extract tool_result content from a Claude Code transcript JSONL.

    These become the grounding sources for hallucination_detector: "what
    actually happened in this session," independent of what the agent's own
    final summary claims happened.

    Best-effort and never raises: a missing, unreadable, or malformed
    transcript yields an empty source list. hallucination_detector reports
    NOT_APPLICABLE (not a false pass) when it has no sources to check
    against, so an empty list here never manufactures a finding.
    """
    sources: list[str] = []
    try:
        text = Path(transcript_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return sources

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        for block in _tool_result_blocks(entry):
            sources.extend(_block_texts(block.get("content"), max_chars))
    return sources


def _tool_result_blocks(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the tool_result blocks carried by one transcript line.

    Real Claude Code transcripts record a tool result as a ``user`` entry
    whose ``message.content`` is a list of Messages-API blocks, one or more of
    them ``{"type": "tool_result", "content": ...}``. A flat top-level
    ``{"type": "tool_result", "content": ...}`` line is also accepted for
    older or hand-built transcripts.
    """
    if entry.get("type") == "tool_result":
        return [entry]
    message = entry.get("message")
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]


def _block_texts(content: Any, max_chars: int) -> list[str]:
    """Pull the text out of a tool_result's content (a string or a block list).

    Non-text blocks (images, tool references) carry no groundable text and
    are skipped rather than stringified.
    """
    if isinstance(content, str):
        return [content[:max_chars]] if content else []
    texts: list[str] = []
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type", "text") == "text" and isinstance(block.get("text"), str):
                if block["text"]:
                    texts.append(block["text"][:max_chars])
    return texts


def check_stop_hook(payload: dict[str, Any]) -> dict[str, Any]:
    """Ground a Claude Code Stop-hook payload's final message and return a
    signed Proof Bundle plus a short summary of what was found.

    `payload` is the JSON object Claude Code writes to the hook's stdin (see
    https://code.claude.com/docs/en/hooks) -- only `last_assistant_message`
    and `transcript_path` are read here; any other/missing fields degrade
    gracefully rather than raising, since a hook must never crash a session.

    Returns:
        {
            "bundle": dict,               # the (unsigned) Proof Bundle
            "verdict": str,                # the aggregate verdict
            "failing_records": list[dict], # verdict_records with verdict == FAIL
            "sources_count": int,          # how many transcript sources were found
        }
    """
    answer = payload.get("last_assistant_message") or ""
    transcript_path = payload.get("transcript_path") or ""
    sources = extract_transcript_sources(transcript_path) if transcript_path else []

    verifiers = [HallucinationDetector(), SymbolicSolver()]
    ctx = VerificationContext(sources=sources)
    bundle = verify_output(answer, verifiers=verifiers, context=ctx, model="claude-code-session")

    verification = bundle.get("verification") or {}
    aggregate = verification.get("aggregate") or {}
    records = verification.get("verdict_records") or []
    failing_records = [r for r in records if r.get("verdict") == "FAIL"]

    return {
        "bundle": bundle,
        "verdict": aggregate.get("verdict"),
        "failing_records": failing_records,
        "sources_count": len(sources),
    }
