"""Real, deterministic verifier engines (ported into the canonical core).

These are model-free engines that recompute an answer's checkable specifics
out-of-band and decide PASS/FAIL on their own — they never trust a model's
self-report. They complete perathos's verifier set alongside CrossExaminer (122)
and ClaimEntailmentVerifier (124):

  SymbolicSolver        (123) — recompute arithmetic claims, flag wrong ones.
  HallucinationDetector (125) — extractive grounding: each of the answer's
                                specifics (money, %, years, durations, quotes)
                                must appear in the sources AS THE SAME KIND of
                                token (a duration is grounded only by a source
                                duration, not by a like-digited dollar amount);
                                optional entailment hook.
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
import math
import re
from functools import lru_cache
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
# Note: `%` is in the char class so modulo expressions ("17 % 5 = 2") parse; the
# evaluator already supports ast.Mod. A bare percentage like "3.2%" can't form a
# valid binary expression, so it fails to parse and is skipped (never flagged).
_EQ_RE = re.compile(
    r"([0-9(][0-9\s\.\,\+\-\*/×x()%]*?)\s*(?:==|=|equals|is equal to|is)\s*(-?[0-9][0-9\,\.]*)",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"\b0[xX][0-9a-fA-F]+\b")
# A comma that is NOT a clean thousands separator (not followed by exactly 3
# digits then a non-digit/end). Its presence means the number is ambiguous
# (decimal comma vs grouping) — we fail closed and skip rather than guess.
_AMBIG_COMMA = re.compile(r",(?!\d{3}(?:\D|$))")
# Characters that, adjacent to a captured number, mean we grabbed a FRAGMENT of a
# larger token (scientific notation "2e3", a caret power "10^3", a decimal, or an
# identifier). Matching a fragment and recomputing it would false-flag a correct
# answer, so such matches are skipped.
_FRAGMENT_ADJ = set(".^")
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
            # Fail closed on fragments: if either captured number is glued to a
            # letter/digit/`.`/`^` (i.e. part of "2e3", "10^3", "x12", a decimal),
            # we grabbed a fragment — skip rather than recompute a misread.
            lo, hi = match.start(1), match.end(2)
            if lo > 0 and (text[lo - 1].isalnum() or text[lo - 1] in _FRAGMENT_ADJ):
                continue
            if hi < len(text) and (text[hi].isalnum() or text[hi] in _FRAGMENT_ADJ):
                continue
            expr = match.group(1).strip()
            if _AMBIG_COMMA.search(expr) or _AMBIG_COMMA.search(match.group(2)):
                continue  # ambiguous comma — fail closed, don't guess decimal vs thousands
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

# Common currency symbols, not just `$` — a fabricated "€900" must be checkable.
_MONEY_RE = re.compile(r"[$€£¥]\s?\d[\d,]*(?:\.\d+)?")
_CURRENCY_CHARS = "$€£¥"
_PERCENT_RE = re.compile(r"\d+(?:\.\d+)?\s?%")
_HD_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")
# Capture the number AND the unit, and tolerate a hyphen ("90-day") or an
# intervening word ("5 business days"), so durations match like-with-like.
_DURATION_RE = re.compile(
    r"\b(\d[\d,]*)\s*-?\s*(?:[A-Za-z]+\s+)?"
    r"(day|days|week|weeks|month|months|year|years|hour|hours|minute|minutes)\b",
    re.IGNORECASE,
)
_QUOTE_RE = re.compile(r"\"([^\"]{4,}?)\"")

_DUR_FAMILY = {
    "day": "day", "days": "day", "week": "week", "weeks": "week",
    "month": "month", "months": "month", "year": "year", "years": "year",
    "hour": "hour", "hours": "hour", "minute": "minute", "minutes": "minute",
}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _parse_money(tok: str) -> Optional[float]:
    for ch in _CURRENCY_CHARS:
        tok = tok.replace(ch, "")
    try:
        return float(tok.replace(",", "").replace(" ", ""))
    except ValueError:
        return None


def _parse_percent(tok: str) -> Optional[float]:
    try:
        return float(tok.replace("%", "").replace(" ", ""))
    except ValueError:
        return None


def _parse_duration(m: "re.Match[str]") -> Optional[tuple]:
    try:
        num = float(m.group(1).replace(",", ""))
    except ValueError:
        return None
    family = _DUR_FAMILY.get(m.group(2).lower())
    return (num, family) if family else None


def _num_grounded(value: float, source_values: set) -> bool:
    return any(abs(value - s) <= 1e-9 * max(1.0, abs(value)) for s in source_values)


def _dur_grounded(pair: tuple, source_pairs: set) -> bool:
    num, family = pair
    return any(fam == family and abs(num - n) <= 1e-9 * max(1.0, abs(num))
              for n, fam in source_pairs)


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
        # Extract the source's specifics PER KIND so a claim is only ever grounded
        # by a token of its own kind. (The old digit-soup let a fabricated duration
        # "90 days" be grounded by an unrelated "$90" — a substring collision.)
        src_money = {v for m in _MONEY_RE.finditer(joined)
                     if (v := _parse_money(m.group(0))) is not None}
        src_percent = {v for m in _PERCENT_RE.finditer(joined)
                       if (v := _parse_percent(m.group(0))) is not None}
        src_years = {int(y) for y in _HD_YEAR_RE.findall(joined)}
        src_durations = {p for m in _DURATION_RE.finditer(joined)
                         if (p := _parse_duration(m)) is not None}
        src_lower = _norm(joined)
        checked: List[dict] = []
        unsupported: List[dict] = []

        def record(kind: str, raw: str, supported: bool) -> None:
            entry = {"kind": kind, "claim": raw, "supported": supported}
            checked.append(entry)
            if not supported:
                unsupported.append(entry)

        for m in _MONEY_RE.finditer(text):
            v = _parse_money(m.group(0))
            record("money", m.group(0), v is not None and _num_grounded(v, src_money))
        for m in _PERCENT_RE.finditer(text):
            v = _parse_percent(m.group(0))
            record("percent", m.group(0), v is not None and _num_grounded(v, src_percent))
        for m in _HD_YEAR_RE.finditer(text):
            record("year", m.group(0), int(m.group(0)) in src_years)
        for m in _DURATION_RE.finditer(text):
            p = _parse_duration(m)
            record("duration", m.group(0), p is not None and _dur_grounded(p, src_durations))
        for m in _QUOTE_RE.finditer(text):
            q = _norm(m.group(1))
            record("quote", m.group(1), (q in src_lower) if q else True)

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

def _reject_nonfinite(_constant: str) -> Any:  # NaN/Infinity/-Infinity aren't valid JSON
    raise ValueError(f"non-finite JSON literal {_constant!r} is not allowed")


def _strict_loads(text: str) -> Any:
    # Reject the json stdlib's NaN/Infinity extension — it is not valid JSON and
    # a non-finite number must not silently satisfy a {"type": "number"} schema.
    return json.loads(text, parse_constant=_reject_nonfinite)


def _has_nonfinite(obj: Any) -> bool:
    if isinstance(obj, float):
        return not math.isfinite(obj)
    if isinstance(obj, dict):
        return any(_has_nonfinite(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_nonfinite(v) for v in obj)
    return False


def _extract_json(text: str) -> Any:
    text = text.strip()
    try:
        return _strict_loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    starts = [i for i in (text.find("{"), text.find("[")) if i != -1]
    ends = [i for i in (text.rfind("}"), text.rfind("]")) if i != -1]
    if starts and ends:
        start, end = min(starts), max(ends)
        if end > start:
            try:
                return _strict_loads(text[start:end + 1])
            except (json.JSONDecodeError, ValueError):
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
        if _has_nonfinite(obj):
            return self._engine_result("fail", "answer contains a non-finite number (NaN/Infinity)",
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

# Curated earliest-existence dates. Conservative (early) on purpose so a clean
# mention is never wrongly flagged; the check only fires when a term predates its
# earliest plausible existence. Terms are unambiguous neologisms or multi-word
# phrases — homographs ("tablet"/"drone"/"stream") are deliberately omitted so a
# word-boundary match can't false-fire on an everyday word. ctx.timeline extends
# or overrides this per call for domain-specific terms, so coverage isn't fixed.
_TIMELINE: dict = {
    "printing press": 1440, "telescope": 1608, "steam engine": 1712,
    "photograph": 1826, "telegraph": 1837, "telephone": 1876,
    "automobile": 1886, "car": 1886, "radio": 1895, "airplane": 1903,
    "television": 1927, "jet engine": 1939, "nuclear weapon": 1945,
    "atomic bomb": 1945, "computer": 1945, "transistor": 1947,
    "solar panel": 1954, "hard drive": 1956, "satellite": 1957,
    "video game": 1958, "laser": 1960, "communications satellite": 1962,
    "email": 1971, "microprocessor": 1971, "space station": 1971,
    "mobile phone": 1973, "cell phone": 1973, "barcode": 1974,
    "digital camera": 1975, "personal computer": 1975, "gps": 1978,
    "spreadsheet": 1979, "space shuttle": 1981, "touchscreen": 1982,
    "compact disc": 1982, "internet": 1983, "dna test": 1984,
    "camcorder": 1983, "3d printer": 1986, "3d printing": 1986,
    "virtual reality": 1987, "world wide web": 1989, "gps navigation": 1989,
    "web browser": 1990, "hubble telescope": 1990, "augmented reality": 1990,
    "search engine": 1990, "webcam": 1991, "text message": 1992,
    "mp3": 1993, "qr code": 1994, "dvd": 1995, "wiki": 1995, "usb": 1996,
    "social media": 1997, "wi-fi": 1997, "wifi": 1997, "hybrid car": 1997,
    "mars rover": 1997, "weblog": 1997, "blog": 1997, "mp3 player": 1998,
    "bluetooth": 1999, "emoji": 1999, "smartwatch": 2000, "video call": 2003,
    "podcast": 2004, "smartphone": 2007, "e-reader": 2007, "hashtag": 2007,
    "cryptocurrency": 2009, "bitcoin": 2009, "blockchain": 2009,
    "fitness tracker": 2009, "self-driving car": 2009, "tablet computer": 2010,
    "quadcopter": 2010, "voice assistant": 2011, "crispr": 2012, "nft": 2014,
    "smart speaker": 2014, "reusable rocket": 2015, "vr headset": 2016,
    "large language model": 2018, "mrna vaccine": 2020, "chatgpt": 2022,
}
_TC_YEAR_RE = re.compile(r"\b(1[0-9]{3}|20[0-9]{2})\b")
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")


@lru_cache(maxsize=512)
def _term_pattern(term: str) -> "re.Pattern[str]":
    """A plural- and hyphen-tolerant, word-bounded matcher for a timeline term.

    Plurals: always allow a trailing "s"; allow "es" only when the singular ends
    in s/x/z/ch/sh/o — so "car" matches "cars" but NOT "cares", while "smartwatch"
    matches "smartwatches". A space in the term matches any run of whitespace.
    The trailing \\b after the suffix keeps "cards"/"scared" from matching "car".
    """
    body = re.escape(term).replace(r"\ ", r"\s+")
    suffix = r"(?:e?s)?" if re.search(r"(?:s|x|z|ch|sh|o)$", term) else r"s?"
    return re.compile(r"\b" + body + suffix + r"\b")


def _term_in(term: str, variants: tuple) -> bool:
    pat = _term_pattern(term)
    return any(pat.search(v) for v in variants)


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
            # Match against the raw text plus hyphen-normalized variants so
            # "smart-watch" (-> "smartwatch") and "qr-code" (-> "qr code") are
            # caught without a homograph false-firing.
            variants = (low, low.replace("-", " "), re.sub(r"(?<=\w)-(?=\w)", "", low))
            for term, earliest in timeline.items():
                if _term_in(term, variants):
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
