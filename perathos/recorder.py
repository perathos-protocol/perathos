"""Agent flight recorder: a signed, hash-chained receipt for every tool call.

Each Claude Code tool call produces two receipts in an append-only JSONL log
(``<cwd>/.perathos/sessions/<session_id>.jsonl``):

* ``pre``  -- written by the PreToolUse hook: which tool, a hash of its
  arguments, before it runs.
* ``post`` -- written by the PostToolUse hook: a hash of what it returned.

At the end of every turn (Stop) and at SessionEnd a ``checkpoint`` receipt is
appended and signed with the local Ed25519 key. Every receipt carries the hash
of the one before it, so editing, reordering or deleting any receipt breaks
the chain, and each signed checkpoint commits to everything before it.

Only hashes of arguments and results are stored, never the content. Whoever
holds the original content can later prove it matches; nobody reading the log
learns it. Caveat: a short, guessable argument (``ls``) can be confirmed by
hashing guesses.

Honest limits (v1):
  * Truncation after the last checkpoint is not detectable from the log alone.
    A ``<session_id>.head.json`` witness records the latest checkpoint, but an
    attacker with write access can delete it too. External timestamping of the
    checkpoint (planned) closes this gap.
  * Timestamps come from the local clock.
  * The signer proves which key sealed the log, not which model ran. The
    ``model`` field is read from the transcript and is self-reported.

Encoding: receipts contain only ASCII keys, strings, integers, booleans and
null, so the canonical JSON used here (sorted keys, no whitespace, UTF-8)
coincides with RFC 8785 (JCS) and can be reproduced in any language.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes

RECEIPT_VERSION = "perathos.receipt/v1"
GENESIS_HASH = "0" * 64
AGENT_CLAUDE_CODE = "claude-code"

_SESSION_ID_RE = re.compile(r"[^A-Za-z0-9._-]")
_LOCK_TIMEOUT_S = 5.0
_STALE_LOCK_S = 30.0
_MODEL_SCAN_BYTES = 512 * 1024


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(value: Any) -> str:
    """Hash tool arguments or results deterministically.

    Strings are hashed as UTF-8. Anything else is hashed as canonical JSON;
    values canonical JSON rejects (NaN, non-string keys) fall back to a
    sorted, ``str``-coerced dump so recording never fails.
    """
    if value is None:
        return _sha256(b"null")
    if isinstance(value, str):
        return _sha256(value.encode("utf-8"))
    try:
        return _sha256(canonical_bytes(value))
    except (TypeError, ValueError):
        dumped = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
        return _sha256(dumped.encode("utf-8"))


def receipt_hash(receipt: dict[str, Any]) -> str:
    """Hash a receipt body: every field except ``receipt_hash`` and ``signature``."""
    body = {k: v for k, v in receipt.items() if k not in ("receipt_hash", "signature")}
    return _sha256(canonical_bytes(body))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Log location and locking
# --------------------------------------------------------------------------- #

def safe_session_id(session_id: Any) -> str:
    sid = _SESSION_ID_RE.sub("_", str(session_id or "unknown"))[:128]
    return sid or "unknown"


def session_log_path(cwd: str | os.PathLike, session_id: Any) -> Path:
    return Path(cwd) / ".perathos" / "sessions" / f"{safe_session_id(session_id)}.jsonl"


def head_path_for(log_path: Path) -> Path:
    return log_path.with_name(log_path.name[: -len(".jsonl")] + ".head.json")


class _FileLock:
    """Cross-platform exclusive lock using an O_EXCL lock file.

    Claude Code can run tool calls (and so hooks) in parallel; without a lock
    two hooks could both read the same tail and fork the chain.
    """

    def __init__(self, path: Path):
        self.path = path.with_name(path.name + ".lock")
        self._fd: int | None = None

    def __enter__(self) -> _FileLock:
        deadline = time.monotonic() + _LOCK_TIMEOUT_S
        while True:
            try:
                self._fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except (FileExistsError, PermissionError):
                # On Windows, opening a lock file another process is deleting
                # raises PermissionError rather than FileExistsError. Both
                # mean "someone else holds it": wait, never drop the receipt.
                try:
                    if time.time() - self.path.stat().st_mtime > _STALE_LOCK_S:
                        self.path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError(f"could not lock {self.path}") from None
                time.sleep(0.01)

    def __exit__(self, *exc: object) -> None:
        if self._fd is not None:
            os.close(self._fd)
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            pass


def _read_last_line(path: Path) -> str | None:
    """Return the last non-empty line of a file without reading all of it."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0:
                read = min(4096, pos)
                pos -= read
                fh.seek(pos)
                buf = fh.read(read) + buf
                stripped = buf.rstrip(b"\r\n")
                if b"\n" in stripped:
                    return stripped.rsplit(b"\n", 1)[1].decode("utf-8", errors="replace")
            stripped = buf.rstrip(b"\r\n")
            return stripped.decode("utf-8", errors="replace") if stripped else None
    except FileNotFoundError:
        return None


def _tail_state(path: Path) -> tuple[int, str]:
    """(last seq, last receipt_hash) of the log, or (0, GENESIS) when empty.

    A corrupt last line is chained to by the hash of its raw bytes, so the
    corruption stays visible to the verifier instead of being papered over.
    """
    last = _read_last_line(path)
    if last is None:
        return 0, GENESIS_HASH
    try:
        rec = json.loads(last)
        return int(rec["seq"]), str(rec["receipt_hash"])
    except (ValueError, KeyError, TypeError):
        return -1, _sha256(last.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Writing receipts
# --------------------------------------------------------------------------- #

def append_receipt(log_path: Path, fields: dict[str, Any], *, signing_key_hex: str | None = None) -> dict[str, Any]:
    """Append one chained receipt to the log and return it.

    ``fields`` supplies the event-specific body (kind, tool, hashes...).
    ``seq``, ``ts``, ``prev_hash`` and ``receipt_hash`` are filled in here,
    under an exclusive lock. If ``signing_key_hex`` is given, the receipt is
    signed over its ``receipt_hash`` and the signer's public key is bound
    into the hashed body as ``signer``.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with _FileLock(log_path):
        last_seq, prev = _tail_state(log_path)
        receipt: dict[str, Any] = {
            "v": RECEIPT_VERSION,
            **fields,
            "seq": (last_seq + 1) if last_seq >= 0 else 0,
            "ts": _now_iso(),
            "prev_hash": prev,
        }
        if signing_key_hex is not None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            from .signing import sign_hash

            sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
            receipt["signer"] = sk.public_key().public_bytes_raw().hex()
            receipt["receipt_hash"] = receipt_hash(receipt)
            receipt["signature"] = sign_hash(receipt["receipt_hash"], signing_key_hex)
        else:
            receipt["receipt_hash"] = receipt_hash(receipt)
        line = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with open(log_path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        if fields.get("kind") == "checkpoint":
            _write_head(log_path, receipt)
    return receipt


def _write_head(log_path: Path, checkpoint: dict[str, Any]) -> None:
    head = {k: checkpoint[k] for k in ("session_id", "seq", "receipt_hash", "ts") if k in checkpoint}
    if "signature" in checkpoint:
        head["signature"] = checkpoint["signature"]
    target = head_path_for(log_path)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(head, sort_keys=True, indent=2), encoding="utf-8")
    os.replace(tmp, target)


def _model_from_transcript(transcript_path: str | None) -> str | None:
    """Most recent ``message.model`` in the transcript tail (self-reported)."""
    if not transcript_path:
        return None
    try:
        with open(transcript_path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - _MODEL_SCAN_BYTES))
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    for line in reversed(tail.splitlines()):
        if '"model"' not in line:
            continue
        try:
            msg = json.loads(line).get("message")
        except (ValueError, AttributeError):
            continue
        if isinstance(msg, dict) and isinstance(msg.get("model"), str):
            return msg["model"]
    return None


def record_hook_event(payload: dict[str, Any], *, signing_key_hex: str | None = None) -> dict[str, Any] | None:
    """Turn one Claude Code hook payload into a receipt. Returns it, or None.

    PreToolUse -> ``pre``; PostToolUse / PostToolUseFailure -> ``post``;
    Stop / SubagentStop / SessionEnd -> signed ``checkpoint``. Other events
    are ignored. Only checkpoints are signed: a signature commits to the whole
    chain before it, and signing every tool call would add latency for no
    extra guarantee.
    """
    event = payload.get("hook_event_name")
    session_id = safe_session_id(payload.get("session_id"))
    cwd = payload.get("cwd") or "."
    log_path = session_log_path(cwd, session_id)
    base = {"session_id": session_id, "agent": AGENT_CLAUDE_CODE}

    if event == "PreToolUse":
        fields = {
            **base,
            "kind": "pre",
            "tool": str(payload.get("tool_name") or ""),
            "tool_use_id": payload.get("tool_use_id"),
            "args_hash": content_hash(payload.get("tool_input")),
        }
        return append_receipt(log_path, fields)

    if event in ("PostToolUse", "PostToolUseFailure"):
        failed = event == "PostToolUseFailure"
        result = payload.get("error") if failed else payload.get("tool_response")
        fields = {
            **base,
            "kind": "post",
            "tool": str(payload.get("tool_name") or ""),
            "tool_use_id": payload.get("tool_use_id"),
            "args_hash": content_hash(payload.get("tool_input")),
            "result_hash": content_hash(result),
            "status": "error" if failed else "ok",
        }
        return append_receipt(log_path, fields)

    if event in ("Stop", "SubagentStop", "SessionEnd"):
        fields = {
            **base,
            "kind": "checkpoint",
            "event": event,
            "model": _model_from_transcript(payload.get("transcript_path")),
        }
        return append_receipt(log_path, fields, signing_key_hex=signing_key_hex)

    return None


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #

@dataclass
class SessionReport:
    path: str
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    session_id: str | None = None
    receipts: int = 0
    tool_calls: int = 0
    checkpoints: int = 0
    signed_checkpoints: int = 0
    sealed_through: int = 0
    unsealed_tail: int = 0
    signers: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    tools: dict[str, int] = field(default_factory=dict)
    first_ts: str | None = None
    last_ts: str | None = None

    def fail(self, msg: str) -> None:
        self.valid = False
        self.errors.append(msg)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _check_checkpoint_signature(rec, where, report, *, require_signed, expected_verify_key, trust_store) -> None:
    from .signing import verify_signature

    sig = rec.get("signature")
    if sig is None:
        if require_signed:
            report.fail(f"ERR_UNSIGNED at {where}: checkpoint has no signature")
        return
    if not isinstance(sig, dict):
        report.fail(f"ERR_BAD_SIGNATURE at {where}")
        return
    ok, err = verify_signature(str(rec.get("receipt_hash")), sig)
    if not ok:
        report.fail(f"{err} at {where}")
        return
    vk = sig.get("verify_key")
    if rec.get("signer") != vk:
        report.fail(f"ERR_SIGNER_MISMATCH at {where}: signature key differs from the bound signer")
    if expected_verify_key is not None and vk != expected_verify_key:
        report.fail(f"ERR_UNEXPECTED_SIGNER at {where}")
    if trust_store is not None:
        from .keytrust import kid_for

        vk_bytes = bytes.fromhex(vk)
        if trust_store.get(kid_for(vk_bytes)) != vk_bytes:
            report.fail(f"ERR_UNTRUSTED_SIGNER at {where}")
    if vk not in report.signers:
        report.signers.append(vk)
    report.signed_checkpoints += 1


def verify_session(
    log_path: str | os.PathLike,
    *,
    expected_verify_key: str | None = None,
    trust_store=None,
    require_signed: bool = True,
    check_head: bool = True,
) -> SessionReport:
    """Verify a session log end to end.

    For every receipt: it parses; its version is known; ``seq`` runs 1, 2, 3...
    with no gaps; ``prev_hash`` equals the previous receipt's hash (the first
    equals GENESIS); ``receipt_hash`` recomputes; the session id never
    changes; timestamps never go backwards. For every checkpoint: the
    signature validates over its hash, the key matches the bound ``signer``,
    and (optionally) matches ``expected_verify_key`` or a trust store.

    With ``require_signed`` (the default) a log with no signed checkpoint, or
    with any unsigned checkpoint, is invalid. Receipts after the last
    checkpoint are reported as an unsealed tail (a warning: the session may
    still be running). If a ``.head.json`` witness exists, a log that ends
    before the witnessed checkpoint is reported as truncated.
    """
    path = Path(log_path)
    report = SessionReport(path=str(path))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        report.fail(f"ERR_UNREADABLE: {exc}")
        return report

    prev = GENESIS_HASH
    expected_seq = 1
    last_ts = ""
    open_pre: dict[str, str] = {}
    checkpoint_hashes: dict[int, str] = {}

    for lineno, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            rec = None
        if not isinstance(rec, dict):
            report.fail(f"ERR_MALFORMED at line {lineno}: not a JSON object")
            prev = _sha256(raw.encode("utf-8"))
            expected_seq += 1
            continue
        report.receipts += 1
        seq = rec.get("seq")
        where = f"seq {seq} (line {lineno})"

        if rec.get("v") != RECEIPT_VERSION:
            report.fail(f"ERR_VERSION at {where}: {rec.get('v')!r}")
        if seq != expected_seq:
            report.fail(f"ERR_SEQ at {where}: expected {expected_seq} (a receipt is missing, duplicated or reordered)")
        if rec.get("prev_hash") != prev:
            report.fail(f"ERR_CHAIN at {where}: prev_hash does not match the previous receipt")
        try:
            recomputed = receipt_hash(rec)
        except (TypeError, ValueError):
            recomputed = None
        if recomputed != rec.get("receipt_hash"):
            report.fail(f"ERR_RECEIPT_HASH at {where}: receipt was modified")

        sid = rec.get("session_id")
        if report.session_id is None:
            report.session_id = sid
        elif sid != report.session_id:
            report.fail(f"ERR_SESSION_ID at {where}: {sid!r} != {report.session_id!r}")

        ts = str(rec.get("ts") or "")
        if last_ts and ts < last_ts:
            report.fail(f"ERR_TIME at {where}: timestamp goes backwards")
        last_ts = max(last_ts, ts)
        report.first_ts = report.first_ts or ts
        report.last_ts = ts

        kind = rec.get("kind")
        if kind == "pre":
            report.tool_calls += 1
            tool = str(rec.get("tool") or "")
            report.tools[tool] = report.tools.get(tool, 0) + 1
            if rec.get("tool_use_id"):
                open_pre[str(rec["tool_use_id"])] = tool
        elif kind == "post":
            tuid = rec.get("tool_use_id")
            if tuid and str(tuid) not in open_pre:
                report.warnings.append(f"result without a matching call at {where}")
            open_pre.pop(str(tuid), None)
        elif kind == "checkpoint":
            report.checkpoints += 1
            if isinstance(seq, int):
                checkpoint_hashes[seq] = str(rec.get("receipt_hash"))
                report.sealed_through = seq
            model = rec.get("model")
            if isinstance(model, str) and model not in report.models:
                report.models.append(model)
            _check_checkpoint_signature(
                rec, where, report,
                require_signed=require_signed,
                expected_verify_key=expected_verify_key,
                trust_store=trust_store,
            )
        else:
            report.fail(f"ERR_KIND at {where}: unknown kind {kind!r}")

        prev = str(rec.get("receipt_hash"))
        expected_seq = (seq + 1) if isinstance(seq, int) else expected_seq + 1

    if report.receipts == 0:
        report.fail("ERR_EMPTY: no receipts")
    elif require_signed and report.signed_checkpoints == 0:
        report.fail("ERR_UNSIGNED: no signed checkpoint seals this log")
    report.unsealed_tail = max(0, (expected_seq - 1) - report.sealed_through)
    if report.unsealed_tail:
        report.warnings.append(f"{report.unsealed_tail} receipt(s) after the last checkpoint are not sealed yet")
    if open_pre:
        report.warnings.append(f"{len(open_pre)} tool call(s) have no result receipt (failed, denied or interrupted)")
    if len(report.signers) > 1:
        report.warnings.append(f"{len(report.signers)} different keys signed checkpoints in this log")

    if check_head and path.name.endswith(".jsonl"):
        hp = head_path_for(path)
        if hp.exists():
            try:
                head = json.loads(hp.read_text(encoding="utf-8"))
                hseq, hhash = int(head["seq"]), str(head["receipt_hash"])
            except (OSError, ValueError, KeyError, TypeError):
                report.warnings.append("head witness file is unreadable")
            else:
                if checkpoint_hashes.get(hseq) != hhash:
                    if hseq > report.sealed_through:
                        report.fail(
                            f"ERR_TRUNCATED: the head witness records checkpoint seq {hseq}, "
                            f"but the log is sealed only through seq {report.sealed_through}"
                        )
                    else:
                        report.fail(f"ERR_HEAD_MISMATCH: checkpoint seq {hseq} differs from the head witness")
    return report
