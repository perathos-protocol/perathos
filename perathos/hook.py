"""Lean entry point for agent hooks: ``perathos-hook record [--guard] [--anchor]``.

Agent hooks run on every tool call, so start-up time matters. This module
avoids click and the verifier engines and imports only what recording needs.
``perathos hooks record`` calls the same function, so behaviour is identical.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO


def _local_verify_key() -> str | None:
    try:
        vk = (Path.home() / ".perathos" / "keys" / "verify.key").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return vk if len(vk) == 64 else None


def _trusted_keys() -> set[str] | None:
    from .approvers import trusted_approver_keys
    return trusted_approver_keys()


def _signing_key():
    """The recorder's signer: the local key file, or a configured remote signer.

    The common case (no remote signer configured) reads the key file directly;
    storage.py pulls in more than a hook needs.
    """
    import os

    from .approvers import get_config
    spec = os.environ.get("PERATHOS_SIGNER") or get_config().get("signer") or "local"
    if spec != "local":
        try:
            from .signers import signer_from_spec
            return signer_from_spec(spec)
        except Exception as exc:  # noqa: BLE001 -- seal unsigned rather than crash the turn
            print(f"perathos recorder: signer {spec!r} unavailable: {exc}", file=sys.stderr)
            return None
    try:
        sk = (Path.home() / ".perathos" / "keys" / "signing.key").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return sk if len(sk) == 64 and all(c in "0123456789abcdef" for c in sk) else None


def run_record(raw: str, *, guard: bool, anchor: bool, out: TextIO, err: TextIO) -> None:
    """Record one Claude Code hook payload. Never raises; never exits non-zero.

    Prints a PreToolUse deny decision when the guard blocks a call (emitted even
    if recording fails: the guard fails closed); otherwise prints nothing.
    """
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict):
        return
    event = payload.get("hook_event_name")

    decision = None
    if guard and event == "PreToolUse":
        try:
            from .guard import decide
            decision = decide(str(payload.get("tool_name") or ""), payload.get("tool_input"),
                              payload.get("cwd") or ".", trusted_key=_trusted_keys())
        except Exception as exc:  # noqa: BLE001 -- a broken guard must not brick the agent
            print(f"perathos guard: {type(exc).__name__}: {exc}", file=err)

    receipt = None
    try:
        from .recorder import record_hook_event
        sk_hex = _signing_key() if event in ("Stop", "SubagentStop", "SessionEnd") else None
        receipt = record_hook_event(payload, signing_key_hex=sk_hex,
                                    guard_decision=decision.receipt_field() if decision else None)
    except Exception as exc:  # noqa: BLE001 -- a recorder must never break the session
        print(f"perathos recorder: {type(exc).__name__}: {exc}", file=err)

    if decision is not None and decision.decision == "deny":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": decision.reason,
        }}), file=out)

    if anchor and receipt and receipt.get("kind") == "checkpoint" and receipt.get("signature"):
        try:
            from .anchor import anchor_checkpoint, default_anchors_path
            anchor_checkpoint(receipt, default_anchors_path(receipt["session_id"]), timeout=8)
        except Exception as exc:  # noqa: BLE001 -- the timestamp service may be down; never fail the turn
            print(f"perathos anchor: {type(exc).__name__}: {exc} (run 'perathos session anchor' later)", file=err)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != "record" or any(a not in ("--guard", "--anchor") for a in args[1:]):
        print("usage: perathos-hook record [--guard] [--anchor]   (reads a hook payload on stdin)", file=sys.stderr)
        return 0  # never fail an agent turn over a usage error
    run_record(sys.stdin.read(), guard="--guard" in args, anchor="--anchor" in args, out=sys.stdout, err=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
