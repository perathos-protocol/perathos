#!/usr/bin/env python3
"""MCP server exposing Perathos VRL verification as tools for any MCP client
(Claude Code, Claude Desktop, or any other client that speaks the Model
Context Protocol).

Two tools, matching the two things a caller actually wants to do:

  perathos_verify_answer  -- check an arbitrary AI answer out-of-band with
                              the real, deterministic engines (never trusts
                              the model's own self-report), optionally
                              signing the resulting Proof Bundle.
  perathos_verify_bundle  -- re-verify an existing signed Proof Bundle's
                              hash chain and signature offline.

Requires the optional `mcp` extra: pip install perathos[mcp]
Run directly (stdio transport): perathos-mcp
"""
from __future__ import annotations

import json
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from mcp.server.fastmcp import FastMCP

from .bundle import verify_bundle as _verify_bundle
from .errors import explain_error as _explain_error
from .engines import HallucinationDetector, SchemaValidator, SymbolicSolver, TemporalConsistency
from .pipeline import CONJUNCTION, verify_output
from .storage import load_signing_key
from .verifiers import VerificationContext

mcp = FastMCP("perathos_mcp")

# The four real, computed engines -- see docs on perathos-protocol/training-ops's
# VERIFICATION_STATUS.md for what each does and does not catch. The other
# three verifiers in the original taxonomy (cross_examiner, knowledge_graph,
# model_fingerprinter) have no engine yet and are never run here.
_REAL_ENGINES = [HallucinationDetector(), SymbolicSolver(), SchemaValidator(), TemporalConsistency()]


class VerifyAnswerInput(BaseModel):
    """Input for verify_answer."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    answer: str = Field(..., description="The AI-generated answer text to check.", min_length=1)
    input_text: Optional[str] = Field(
        default="", description="The original prompt/question that produced `answer` (optional)."
    )
    sources: Optional[List[str]] = Field(
        default=None,
        description=(
            "Grounding source documents, if any -- enables hallucination_detector "
            "to flag amounts/dates/quoted spans in `answer` not supported by these."
        ),
    )
    json_schema: Optional[str] = Field(
        default=None,
        description=(
            "A JSON Schema (as a JSON string) `answer` must conform to, if `answer` is "
            "structured output -- enables schema_validator."
        ),
    )
    model: str = Field(default="unspecified", description="An identifier for the model that produced `answer`.")
    sign: bool = Field(
        default=False,
        description=(
            "Sign the resulting bundle with the local Perathos key (run `perathos keygen` once first). "
            "If no key exists, the bundle is returned unsigned rather than erroring."
        ),
    )


class VerifyBundleInput(BaseModel):
    """Input for verify_bundle."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    bundle_json: str = Field(..., description="The Proof Bundle as a JSON string.", min_length=1)
    expected_verify_key: Optional[str] = Field(
        default=None,
        description="Pin the expected signer: reject the bundle unless its signature key equals this 64-char hex key.",
    )
    allow_unsigned: bool = Field(
        default=False,
        description="Accept an unsigned bundle. Unsigned bundles fail by default because anyone can create one.",
    )


def _run_verify_answer(params: VerifyAnswerInput) -> dict:
    schema_dict = json.loads(params.json_schema) if params.json_schema else None
    ctx = VerificationContext(sources=params.sources or [], schema=schema_dict)
    bundle = verify_output(
        params.answer,
        params.input_text or "",
        verifiers=_REAL_ENGINES,
        context=ctx,
        mode=CONJUNCTION,
        model=params.model,
    )
    if params.sign:
        try:
            sk_hex = load_signing_key()
            from .bundle import sign_bundle

            bundle = sign_bundle(bundle, sk_hex)
        except FileNotFoundError:
            pass  # No local key yet (run `perathos keygen`) -- return unsigned rather than erroring.
    return bundle


@mcp.tool(
    name="perathos_verify_answer",
    annotations={
        "title": "Verify an AI Answer",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def perathos_verify_answer(params: VerifyAnswerInput) -> str:
    """Check an AI-generated answer with real, deterministic verifier engines
    and return a tamper-evident Proof Bundle.

    Runs the answer out-of-band through the four real Perathos engines --
    hallucination_detector (extractive grounding against `sources`),
    symbolic_solver (recomputes stated arithmetic), schema_validator
    (validates against `json_schema` if given), and temporal_consistency
    (flags anachronisms). The verdict is driven ONLY by what these engines
    actually compute -- never by the answer's own claims about itself.

    Args:
        params (VerifyAnswerInput): Validated input containing:
            - answer (str): the AI answer to check
            - input_text (Optional[str]): the original prompt (optional)
            - sources (Optional[List[str]]): grounding documents (optional)
            - json_schema (Optional[str]): a JSON Schema as a string (optional)
            - model (str): an identifier for the answering model
            - sign (bool): sign the bundle with the local key if one exists

    Returns:
        str: The Proof Bundle as JSON (perathos bundle_version "2.0"), including:
        {
            "bundle_id": str, "verdict": "PASS"|"FAIL"|"INCONCLUSIVE"|"WARN",
            "verification": {"aggregate": {...}, "verdict_records": [
                {"verifier_name": str,  # e.g. "Symbolic Solver", "Hallucination Detector"
                 "verdict": "PASS"|"FAIL"|"INCONCLUSIVE"|"WARN", "method": str,
                 "detail": str, "evidence": dict|None, "computed": true}, ...
            ]},
            "provider_signature": {...}   # present only if sign=True and a local key exists
        }

    Examples:
        - Use when: "Check whether this AI answer's arithmetic is correct" ->
          params with answer="The total is 25 * 4 = 100." (no sources needed)
        - Use when: "Does this answer's claims match the source document?" ->
          params with answer=<text>, sources=[<source document text>]
        - Don't use when: you already have a signed bundle and just want to
          re-check it (use perathos_verify_bundle instead)

    Error Handling:
        - Invalid json_schema (not valid JSON) raises a validation error
          before any verification runs.
        - A verifier with nothing to check on this answer reports
          NOT_APPLICABLE, never a false pass.
    """
    bundle = _run_verify_answer(params)
    return json.dumps(bundle, indent=2, sort_keys=True)


@mcp.tool(
    name="perathos_verify_bundle",
    annotations={
        "title": "Verify a Proof Bundle",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def perathos_verify_bundle(params: VerifyBundleInput) -> str:
    """Re-verify a Proof Bundle's hash chain and signature entirely offline.

    Recomputes every hash in the bundle's integrity chain (_trace -> trace_hash
    -> integrity_hash -> bundle_id) and, if the bundle carries a
    provider_signature, checks the Ed25519 signature over integrity_hash.
    Rejects any post-signing edit or re-sign by an unexpected key. This does
    NOT re-run the original verifier engines -- it only checks that the
    bundle's own recorded verdicts have not been tampered with since they
    were computed and signed.

    Args:
        params (VerifyBundleInput): Validated input containing:
            - bundle_json (str): the Proof Bundle as a JSON string
            - expected_verify_key (Optional[str]): pin the expected signer's
              64-char hex public key; rejects the bundle if signed by a
              different key

    Returns:
        str: JSON-formatted result:
        {
            "valid": bool,
            "error_code": str,        # "" if valid, else e.g. "ERR_BAD_SIGNATURE"
            "explanation": str        # human-readable, actionable explanation
        }

    Examples:
        - Use when: "Is this Proof Bundle someone sent me actually valid?" ->
          params with bundle_json=<the bundle's JSON text>
        - Use when: "Was this bundle really signed by the key I expect?" ->
          params with bundle_json=<...>, expected_verify_key=<64-char hex>
        - Don't use when: you have raw answer text with no bundle yet (use
          perathos_verify_answer instead)

    Error Handling:
        - Malformed JSON in bundle_json raises a validation error before any
          verification runs.
        - Every failure mode (tamper detection, missing fields, bad
          signature, untrusted signer) returns valid=False with a specific
          error_code and a plain-language explanation -- never a crash.
    """
    bundle = json.loads(params.bundle_json)
    valid, err = _verify_bundle(
        bundle,
        expected_verify_key=params.expected_verify_key,
        require_signed=not params.allow_unsigned,
    )
    return json.dumps(
        {"valid": valid, "error_code": err, "explanation": _explain_error(err) if err else ""},
        indent=2,
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
