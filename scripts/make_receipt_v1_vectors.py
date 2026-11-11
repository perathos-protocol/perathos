#!/usr/bin/env python
"""Generate the `perathos.receipt/v1` interop test vectors.

Writes docs/specs/vectors/receipt_v1/ (or --out DIR): four cases, each a
session log plus its head witness, and expected.json with the result
`perathos session verify` must give. The logs are written by the real recorder
(perathos/recorder.py, ``record_hook_event``) with a FIXED TEST KEY, a fixed
session id and an injected clock, so re-running produces byte-identical files.
Negative cases are mutated after writing, each so that it fails on one rule.

Usage:
    python scripts/make_receipt_v1_vectors.py [--out DIR]

The signing key below is published on purpose. Never use it for anything real.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Allow running from a checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from perathos import recorder  # noqa: E402
from perathos.keytrust import KmsSigner, LocalSigner  # noqa: E402
from perathos.signers import SignerError  # noqa: E402
from perathos.signing import sign_hash  # noqa: E402

DEFAULT_OUT = (
    Path(__file__).resolve().parent.parent / "docs" / "specs" / "vectors" / "receipt_v1"
)

# FIXED TEST KEYS, published on purpose. Never use them for anything real.
TEST_SIGNING_KEY = hashlib.sha256(
    b"perathos.receipt/v1 test vector signing key"
).hexdigest()
FORGER_SIGNING_KEY = hashlib.sha256(
    b"perathos.receipt/v1 test vector forger key"
).hexdigest()
TEST_VERIFY_KEY = LocalSigner.from_hex(TEST_SIGNING_KEY).public_key.hex()

SESSION_ID = "receipt-v1-vector"
LOG_NAME = f"{SESSION_ID}.jsonl"
HEAD_NAME = f"{SESSION_ID}.head.json"
CLOCK_START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

CASES = (
    "01-valid",
    "02-broken-prev-hash",
    "03-forged-checkpoint-signature",
    "04-unsigned-checkpoint",
)


@contextlib.contextmanager
def _fixed_clock():
    """Replace the recorder's clock: one second per receipt from CLOCK_START."""
    ticks = iter(range(1_000_000))
    original = recorder._now_iso

    def fake_now() -> str:
        t = CLOCK_START + timedelta(seconds=next(ticks))
        return t.isoformat(timespec="microseconds").replace("+00:00", "Z")

    recorder._now_iso = fake_now
    try:
        yield
    finally:
        recorder._now_iso = original


def _failing_signer() -> KmsSigner:
    """A remote signer that is down: it has a public key but cannot sign."""

    def sign_fn(_payload: bytes) -> bytes:
        raise SignerError("signing service unreachable (test vector)")

    return KmsSigner(
        key_id="vector-remote",
        public_key=bytes.fromhex(TEST_VERIFY_KEY),
        sign_fn=sign_fn,
    )


def _record_session(cwd: Path, *, final_signer) -> Path:
    """One Claude Code session through the real hook recorder: 8 receipts.

    seq 1-4 two tool calls, seq 5 Stop checkpoint, seq 6-7 one tool call,
    seq 8 SessionEnd checkpoint (signed with ``final_signer``).
    """

    def payload(event: str, **extra) -> dict:
        return {
            "hook_event_name": event,
            "session_id": SESSION_ID,
            "cwd": str(cwd),
            **extra,
        }

    calls = [
        (
            "Bash",
            "toolu_01",
            {"command": "ls"},
            {"stdout": "README.md\nsrc\n", "stderr": ""},
        ),
        ("Read", "toolu_02", {"file_path": "README.md"}, "# Example project\n"),
    ]
    with _fixed_clock():
        for tool, tuid, tool_input, response in calls:
            recorder.record_hook_event(
                payload(
                    "PreToolUse",
                    tool_name=tool,
                    tool_use_id=tuid,
                    tool_input=tool_input,
                )
            )
            recorder.record_hook_event(
                payload(
                    "PostToolUse",
                    tool_name=tool,
                    tool_use_id=tuid,
                    tool_input=tool_input,
                    tool_response=response,
                )
            )
        recorder.record_hook_event(payload("Stop"), signing_key_hex=TEST_SIGNING_KEY)
        tool_input = {"file_path": "notes.txt", "content": "done\n"}
        recorder.record_hook_event(
            payload(
                "PreToolUse",
                tool_name="Write",
                tool_use_id="toolu_03",
                tool_input=tool_input,
            )
        )
        recorder.record_hook_event(
            payload(
                "PostToolUse",
                tool_name="Write",
                tool_use_id="toolu_03",
                tool_input=tool_input,
                tool_response={"success": True},
            )
        )
        # The signer-failure path prints a warning on stderr; keep the generator quiet.
        with contextlib.redirect_stderr(io.StringIO()):
            recorder.record_hook_event(
                payload("SessionEnd"), signing_key_hex=final_signer
            )
    return recorder.session_log_path(cwd, SESSION_ID)


def _read(log: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write(log: Path, receipts: list[dict]) -> None:
    # Same serialisation as recorder.append_receipt.
    lines = [
        json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for r in receipts
    ]
    with open(log, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(line + "\n" for line in lines))


def _reseal_from(receipts: list[dict], index: int) -> None:
    """Recompute receipt_hash from ``index`` on (re-chaining the ones after it)
    and re-sign every signed checkpoint with the test key, as its holder would."""
    for i in range(index, len(receipts)):
        rec = receipts[i]
        if i > index:
            rec["prev_hash"] = receipts[i - 1]["receipt_hash"]
        rec["receipt_hash"] = recorder.receipt_hash(rec)
        if "signature" in rec:
            rec["signature"] = sign_hash(rec["receipt_hash"], TEST_SIGNING_KEY)


def _flip_last_hex(h: str) -> str:
    return h[:-1] + ("0" if h[-1] != "0" else "1")


def _make_case(name: str, work: Path, out: Path) -> None:
    cwd = work / name
    final_signer = (
        _failing_signer() if name == "04-unsigned-checkpoint" else TEST_SIGNING_KEY
    )
    log = _record_session(cwd, final_signer=final_signer)
    receipts = _read(log)

    if name == "02-broken-prev-hash":
        # seq 3 points at a hash that is not seq 2's. Its own receipt_hash, and
        # everything after it, is recomputed and re-signed with the real key, so
        # the chain link is the only rule broken.
        receipts[2]["prev_hash"] = _flip_last_hex(receipts[2]["prev_hash"])
        _reseal_from(receipts, 2)
        _write(log, receipts)
        recorder._write_head(log, receipts[-1])
    elif name == "03-forged-checkpoint-signature":
        # seq 5: a well-formed Ed25519 signature over the right receipt_hash, but
        # made with another key while verify_key still names the real one.
        cp = receipts[4]
        forged = sign_hash(cp["receipt_hash"], FORGER_SIGNING_KEY)
        cp["signature"] = {**cp["signature"], "signature": forged["signature"]}
        _write(log, receipts)

    dest = out / name
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(log, dest / LOG_NAME)
    # The recorder writes the head witness in text mode (CRLF on Windows): store it with LF.
    head = recorder.head_path_for(log).read_bytes().replace(b"\r\n", b"\n")
    (dest / HEAD_NAME).write_bytes(head)


def _expected() -> dict:
    files = {"log": LOG_NAME, "head": HEAD_NAME}
    case = {
        "01-valid": {
            "description": "A session as the recorder writes it: 2 tool calls, a signed Stop checkpoint, "
            "1 tool call, a signed SessionEnd checkpoint.",
            "rule": None,
            "verdict": "VALID",
            "errors": [],
        },
        "02-broken-prev-hash": {
            "description": "seq 3 has a prev_hash that is not seq 2's receipt_hash (last hex digit changed). "
            "Its receipt_hash and every later receipt were recomputed and the checkpoints "
            "re-signed with the real key, so nothing but the chain link is wrong.",
            "rule": "RECEIPT_V1.md Verification rule 3 (prev_hash chain)",
            "verdict": "INVALID",
            "errors": [
                {
                    "code": "ERR_CHAIN",
                    "seq": 3,
                    "message": "ERR_CHAIN at seq 3 (line 3): prev_hash does not match "
                    "the previous receipt",
                }
            ],
        },
        "03-forged-checkpoint-signature": {
            "description": "The Stop checkpoint at seq 5 carries a well-formed 128-hex Ed25519 signature "
            "over its receipt_hash made with a different key; signature.verify_key and "
            "signer still name the real key.",
            "rule": "RECEIPT_V1.md Verification rule 6 (checkpoint signature)",
            "verdict": "INVALID",
            "errors": [
                {
                    "code": "ERR_BAD_SIGNATURE",
                    "seq": 5,
                    "message": "ERR_BAD_SIGNATURE at seq 5 (line 5)",
                }
            ],
        },
        "04-unsigned-checkpoint": {
            "description": "The SessionEnd checkpoint at seq 8 was written while the remote signer was "
            'down: no signer or signature, signer_error "SignerError" in the hashed body. '
            "The Stop checkpoint at seq 5 is signed.",
            "rule": 'RECEIPT_V1.md Verification rule 7 and "Signer failures"',
            "verdict": "INVALID",
            "errors": [
                {
                    "code": "ERR_UNSIGNED",
                    "seq": 8,
                    "message": "ERR_UNSIGNED at seq 8 (line 8): checkpoint has no signature: "
                    "the recorder's signer failed when it was sealed ('SignerError')",
                }
            ],
            "verdict_with_allow_unsigned": "VALID",
        },
    }
    return {
        "format": recorder.RECEIPT_VERSION,
        "generator": "scripts/make_receipt_v1_vectors.py",
        "verify_key": TEST_VERIFY_KEY,
        "test_signing_key": TEST_SIGNING_KEY,
        "test_signing_key_note": "FIXED TEST KEY, published on purpose. Never use it for anything real.",
        "anchors": "none; verify without --require-anchor",
        "cases": {name: {"files": files, **case[name]} for name in CASES},
    }


def generate(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        # The signer-failure path appends to the local error log; keep that out of ~/.perathos.
        old = os.environ.get("PERATHOS_ERROR_LOG")
        os.environ["PERATHOS_ERROR_LOG"] = str(Path(tmp) / "errors.log")
        try:
            for name in CASES:
                _make_case(name, Path(tmp), out)
        finally:
            if old is None:
                os.environ.pop("PERATHOS_ERROR_LOG", None)
            else:
                os.environ["PERATHOS_ERROR_LOG"] = old
    text = json.dumps(_expected(), indent=2, ensure_ascii=False) + "\n"
    (out / "expected.json").write_bytes(text.encode("utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output directory (default: %(default)s)",
    )
    args = ap.parse_args()
    generate(args.out)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
