"""Real, deterministic verifier engines (ported into the canonical core).

These are model-free engines that recompute an answer's checkable specifics
out-of-band and decide PASS/FAIL on their own — they never trust a model's
self-report. They complete perathos's verifier set alongside CrossExaminer (122)
and ClaimEntailmentVerifier (124):

  SymbolicSolver        (123) — recompute arithmetic claims, flag wrong ones.
  HallucinationDetector (125) — extractive grounding: the answer's specifics
                                (money, %, years, durations, quotes) must appear
                                in the provided sources; optional entailment hook.
  SchemaValidator       (126) — validate JSON output against a declared schema
                                (jsonschema; remote $ref refused — SSRF-safe).
  TemporalConsistency   (127) — flag anachronisms against a reference timeline.

Each runs behind Verifier.run(), so an exception degrades to INCONCLUSIVE and
never to PASS. status maps: pass->PASS, fail->FAIL, skipped->NOT_APPLICABLE.
Structured evidence is canonicalized and bound as an evidence digest so the
verdict is reproducible.

SchemaValidator needs the optional `schema` extra (`pip install perathos[schema]`).
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from typing import Any, Callable, List, Optional

from .canonical import canonical_bytes
from .verdict import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, VerdictRecord
from .verifiers import VerificationContext, Verifier

_STATUS = {"pass": PASS, "fail": FAIL, "skipped": NOT_APPLICABLE, "error": INCONCLUSIVE}


def _digest(obj: Any) -> str:
    return "sha-256:" + hashlib.sha256(canonical_bytes(obj)).hexdigest()


class _Engine(Verifier):
    """Base for ported engines: build a VerdictRecord from an engine status."""

    def _engine_result(self, status: str, detail: str, *, evidence: Optional[dict] = None,
                       confidence_bps: int = 0) -> VerdictRecord:
        digests = [_digest(evidence)] if evidence is not None else []
        return VerdictRecord(
            verifier_id=self.verifier_id,
            verifier_name=self.verifier_name,
            verifier_version=self.verifier_version,
            verdict=_STATUS.get(status, INCONCLUSIVE),
            confidence_bps=confidence_bps,
            method=self.method,
            detail=detail,
            evidence_digests=digests,
            # Carry the raw structured evidence too (bound by the digest above);
            # an auditor/consumer can replay it. Redact at the caller if needed.
            evidence=evidence,
        )


# ── 123 Symbolic Solver ────────────────────────────────────────────────────────

_ALLOWED_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow)
_EQ_RE = re.compile(
    r"([0-9(][0-9\s\.\,\+\-\*/×x()]*?)\s*(?:==|=|equals|is equal to|is)\s*(-?[0-9][0-9\,\.]*)",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
_MAX_EXPR_LEN = 100


def _eval_node(node: ast.AST) -> Optional[float]:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return float(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, _ALLOWED_BINOPS):
        left, right = _eval_node(node.left), _eval_node(node.right)
        if left is None or right is None:
            return None
        try:
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right
            if isinstance(node.op, ast.FloorDiv):
                return left // right
            if isinstance(node.op, ast.Mod):
                return left % right
            if isinstance(node.op, ast.Pow):
                if abs(right) > 64:  # bound exponent — a crafted answer must not DoS
                    return None
                return left ** right
        except (ZeroDivisionError, ValueError, OverflowError):
            return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _eval_node(node.operand)
        if value is None:
            return None
        return value if isinstance(node.op, ast.UAdd) else -value
    return None


def _safe_eval(expr: str) -> Optional[float]:
    if len(expr) > _MAX_EXPR_LEN:
        return None
    # hex (0x10) -> decimal BEFORE turning 'x' into '*', else "0x10" reads as "0*10".
    expr = _HEX_RE.sub(lambda m: str(int(m.group(0), 16)), expr)
    expr = expr.replace("×", "*").replace("x", "*").replace("X", "*").replace(",", "")
    try:
        tree = ast.parse(expr, mode="eval")
    except (SyntaxError, ValueError):
        return None
    return _eval_node(tree.body)


class SymbolicSolver(_Engine):
    verifier_id = 123
    verifier_name = "Symbolic Solver"
    verifier_version = "1.0.0"
    method = "computed:arithmetic-recompute"

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        text = (output if isinstance(output, str) else str(output))[:20000]
        equations: List[dict] = []
        for match in _EQ_RE.finditer(text):
            if len(equations) >= 100:
                break
            expr = match.group(1).strip()
            computed = _safe_eval(expr)
            try:
                claimed = float(match.group(2).replace(",", ""))
            except ValueError:
                continue
            if computed is None:
                continue
            ok = abs(computed - claimed) <= 1e-6 * max(1.0, abs(computed))
            equations.append({"expr": expr, "claimed": claimed, "computed": computed, "ok": ok})
        if not equations:
            return self._engine_result("skipped", "no checkable arithmetic claim found")
        wrong = [e for e in equations if not e["ok"]]
        if wrong:
            w = wrong[0]
            return self._engine_result(
                "fail",
                f"{len(wrong)} of {len(equations)} arithmetic claim(s) are wrong, e.g. "
                f"{w['expr']!r} claims {w['claimed']:g} but computes to {w['computed']:g}",
                evidence={"equations": equations}, confidence_bps=1000,
            )
        return self._engine_result(
            "pass", f"recomputed {len(equations)} arithmetic claim(s); all correct",
            evidence={"equations": equations}, confidence_bps=1000,
        )


# ── 125 Hallucination Detector (extractive grounding) ──────────────────────────

_MONEY_RE = re.compile(r"\$\s?\d[\d,]*(?:\.\d+)?")
_PERCENT_RE = re.compile(r"\d+(?:\.\d+)?\s?%")
_HD_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")
_DURATION_RE = re.compile(
    r"\b(\d[\d,]*)\s?(?:\w+\s+)?(?:day|days|week|weeks|month|months|year|years|hour|hours|minute|minutes)\b",
    re.IGNORECASE,
)
_QUOTE_RE = re.compile(r"\"([^\"]{4,}?)\"")


def _digits(text: str) -> str:
    return re.sub(r"[\s,$%]", "", text.lower())


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


class HallucinationDetector(_Engine):
    verifier_id = 125
    verifier_name = "Hallucination Detector"
    verifier_version = "1.0.0"
    method = "computed:extractive-grounding"

    def __init__(self, entailment_fn: Optional[Callable[[str, str], "bool | None"]] = None):
        # Optional semantic upgrade: entailment_fn(answer, joined_sources) ->
        # True (entailed) / False (contradicted) / None (unknown).
        self.entailment_fn = entailment_fn

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        sources = ctx.sources
        if isinstance(sources, str):
            sources = [sources]
        if not sources or not any(str(s).strip() for s in sources):
            return self._engine_result("skipped", "no grounding sources provided")
        text = output if isinstance(output, str) else str(output)
        joined = " ".join(str(s) for s in sources)
        src_digits, src_lower = _digits(joined), _norm(joined)
        checked: List[dict] = []
        unsupported: List[dict] = []

        def consider(kind: str, raw: str, needle: str, *, numeric: bool) -> None:
            haystack = src_digits if numeric else src_lower
            supported = needle in haystack if needle else True
            entry = {"kind": kind, "claim": raw, "supported": supported}
            checked.append(entry)
            if not supported:
                unsupported.append(entry)

        for m in _MONEY_RE.finditer(text):
            consider("money", m.group(0), _digits(m.group(0)), numeric=True)
        for m in _PERCENT_RE.finditer(text):
            consider("percent", m.group(0), _digits(m.group(0)), numeric=True)
        for m in _HD_YEAR_RE.finditer(text):
            consider("year", m.group(0), m.group(0), numeric=True)
        for m in _DURATION_RE.finditer(text):
            consider("duration", m.group(0), _digits(m.group(1)), numeric=True)
        for m in _QUOTE_RE.finditer(text):
            consider("quote", m.group(1), _norm(m.group(1)), numeric=False)

        if unsupported:
            u = unsupported[0]
            return self._engine_result(
                "fail",
                f"{len(unsupported)} of {len(checked)} specific(s) not grounded in sources, "
                f"e.g. {u['kind']} {u['claim']!r}",
                evidence={"unsupported": unsupported, "n_checked": len(checked)}, confidence_bps=800,
            )

        if callable(self.entailment_fn):
            try:
                raw = self.entailment_fn(text, joined)
            except Exception:
                raw = None  # injected model failed: do NOT fail open to PASS
            entailed = None if raw is None else bool(raw)
            if entailed is False:
                return self._engine_result("fail", "answer is not entailed by the sources (semantic check)",
                                           evidence={"method": "entailment", "n_checked": len(checked)}, confidence_bps=700)
            if entailed is True:
                return self._engine_result("pass", "answer is entailed by the sources (semantic check)",
                                           evidence={"method": "entailment", "n_grounded": len(checked)}, confidence_bps=700)

        if not checked:
            return self._engine_result("skipped", "no checkable specifics (amounts, years, quotes) in the answer")
        return self._engine_result(
            "pass", f"all {len(checked)} checkable specific(s) are grounded in the sources",
            evidence={"n_grounded": len(checked)}, confidence_bps=700,
        )


# ── 126 Schema Validator (jsonschema, SSRF-safe) ───────────────────────────────

def _extract_json(text: str) -> Any:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    starts = [i for i in (text.find("{"), text.find("[")) if i != -1]
    ends = [i for i in (text.rfind("}"), text.rfind("]")) if i != -1]
    if starts and ends:
        start, end = min(starts), max(ends)
        if end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
    return None


class SchemaValidator(_Engine):
    verifier_id = 126
    verifier_name = "Schema Validator"
    verifier_version = "1.0.0"
    method = "computed:json-schema"

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        schema = ctx.schema
        if not isinstance(schema, dict):
            return self._engine_result("skipped", "no JSON Schema declared for this answer")
        try:
            import jsonschema
            from referencing import Registry
            from referencing.exceptions import NoSuchResource
        except ImportError:
            return self._engine_result("error", "jsonschema not installed (pip install perathos[schema])")

        obj = output if isinstance(output, (dict, list)) else _extract_json(str(output))
        if obj is None:
            return self._engine_result("fail", "answer contains no parseable JSON value to validate",
                                       confidence_bps=1000)

        def _refuse_remote(uri: str):  # remote $ref => SSRF/DoS; refuse all
            raise NoSuchResource(ref=uri)

        try:
            validator_cls = jsonschema.validators.validator_for(schema)
            validator_cls.check_schema(schema)
            validator = validator_cls(schema, registry=Registry(retrieve=_refuse_remote))
            validator.validate(obj)
        except jsonschema.ValidationError as exc:
            path = "/".join(str(p) for p in exc.absolute_path) or "<root>"
            return self._engine_result(
                "fail", f"schema violation at {path}: {exc.message}",
                evidence={"path": list(map(str, exc.absolute_path)), "validator": exc.validator},
                confidence_bps=1000,
            )
        except Exception as exc:  # malformed schema, refused remote $ref, recursion
            return self._engine_result("error", f"schema could not be evaluated: {type(exc).__name__}")
        return self._engine_result("pass", "structured output conforms to the declared JSON Schema",
                                   confidence_bps=1000)


# ── 127 Temporal Consistency ───────────────────────────────────────────────────

_TIMELINE: dict = {
    "printing press": 1440, "telescope": 1608, "steam engine": 1712,
    "photograph": 1826, "telegraph": 1837, "telephone": 1876,
    "automobile": 1886, "car": 1886, "radio": 1895, "airplane": 1903,
    "television": 1927, "jet engine": 1939, "nuclear weapon": 1945,
    "atomic bomb": 1945, "computer": 1945, "transistor": 1947,
    "satellite": 1957, "laser": 1960, "email": 1971, "personal computer": 1975,
    "gps": 1978, "internet": 1983, "world wide web": 1989, "dna test": 1984,
    "web browser": 1990, "text message": 1992, "social media": 1997,
    "smartphone": 2007, "cryptocurrency": 2009, "bitcoin": 2009,
}
_TC_YEAR_RE = re.compile(r"\b(1[0-9]{3}|20[0-9]{2})\b")
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")


class TemporalConsistency(_Engine):
    verifier_id = 127
    verifier_name = "Temporal Consistency Checker"
    verifier_version = "1.0.0"
    method = "computed:timeline"

    def _verify(self, output: str, ctx: VerificationContext) -> VerdictRecord:
        text = output if isinstance(output, str) else str(output)
        timeline = dict(_TIMELINE)
        if isinstance(ctx.timeline, dict):
            timeline.update({str(k).lower(): int(v) for k, v in ctx.timeline.items()})
        anachronisms: List[dict] = []
        n_checked = 0
        for sentence in _SENT_SPLIT.split(text):
            low = sentence.lower()
            years = [int(y) for y in _TC_YEAR_RE.findall(sentence)]
            if not years:
                continue
            for term, earliest in timeline.items():
                if re.search(r"\b" + re.escape(term) + r"\b", low):  # word-boundary
                    n_checked += 1
                    bad = [y for y in years if y < earliest]
                    if bad:
                        anachronisms.append({"term": term, "year": min(bad), "earliest": earliest})
        if n_checked == 0:
            return self._engine_result("skipped", "no checkable date/term pairing in the answer")
        if anachronisms:
            a = anachronisms[0]
            return self._engine_result(
                "fail",
                f"anachronism: {a['term']!r} referenced in {a['year']} but not before {a['earliest']}",
                evidence={"anachronisms": anachronisms}, confidence_bps=900,
            )
        return self._engine_result("pass", f"{n_checked} term/date pairing(s) are temporally consistent",
                                   confidence_bps=700)


def all_engines() -> List[Verifier]:
    """The four real engines (SchemaValidator needs the `schema` extra)."""
    return [SymbolicSolver(), HallucinationDetector(), SchemaValidator(), TemporalConsistency()]
