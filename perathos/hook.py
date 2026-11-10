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


def _signing_key(err: TextIO | None = None, *, session_id=None, project=None):
    """The recorder's signer and, if it failed, why: ``(signer or None, error name or None)``.

    The signer is the local key file or a configured remote signer. The common
    case (no remote signer configured) reads the key file directly; storage.py
    pulls in more than a hook needs. A local key that does not exist yet is not
    a failure (checkpoints are unsigned until 'perathos keygen'). A remote
    signer that cannot be reached, or a malformed local key, is: the checkpoint
    is still written, unsigned and marked ``signer_error``, with a warning.
    """
    import os

    from .approvers import get_config
    spec = os.environ.get("PERATHOS_SIGNER") or get_config().get("signer") or "local"
    failure: Exception
    if spec != "local":
        try:
            from .signers import signer_from_spec
            return signer_from_spec(spec), None
        except Exception as exc:  # noqa: BLE001 -- seal unsigned rather than crash the turn
            failure = exc
    else:
        try:
            sk = (Path.home() / ".perathos" / "keys" / "signing.key").read_text(encoding="utf-8").strip()
        except OSError:
            return None, None
        if len(sk) == 64 and all(c in "0123456789abcdef" for c in sk):
            return sk, None
        failure = ValueError("local signing key is malformed")
    from .errlog import log_error
    print(f"perathos recorder: WARNING: signer {spec.split(':')[0]!r} unavailable ({type(failure).__name__}: "
          f"{failure}); checkpoint sealed UNSIGNED and marked signer_error. This session will not verify "
          f"until the signer works.", file=err or sys.stderr)
    log_error("signer", failure, session_id=session_id, project=project)
    return None, type(failure).__name__


def run_record(raw: str, *, guard: bool, anchor: bool, out: TextIO, err: TextIO) -> None:
    """Record one Claude Code hook payload. Never raises; never exits non-zero.

    Prints a PreToolUse deny decision when the guard blocks a call (emitted even
    if recording fails: the guard fails closed); otherwise prints nothing.
    A recording failure is reported on stderr and appended to the local error
    log (``perathos/errlog.py``); the tool call still proceeds.
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
            if decision is not None and decision.decision == "deny":
                from .approvers import get_config
                from .gate import apply_gate
                try:
                    wait = int(get_config().get("gate_wait") or 120)
                except ValueError:
                    wait = 120
                decision = apply_gate(decision, tool=str(payload.get("tool_name") or ""),
                                      args=payload.get("tool_input"), cwd=payload.get("cwd") or ".",
                                      session_id=str(payload.get("session_id") or ""), agent_name="claude-code",
                                      wait_seconds=wait)
        except Exception as exc:  # noqa: BLE001
            # Fail closed: if the guard itself crashes we cannot tell whether the
            # call is destructive, so it is denied (and recorded as denied).
            from .guard import Decision
            print(f"perathos guard: {type(exc).__name__}: {exc}", file=err)
            decision = Decision("deny", "guard.error", None, f"perathos guard: blocked because the guard itself failed ({type(exc).__name__}: {exc}). The guard fails closed; fix the error or remove --guard.")

    receipt = None
    try:
        from .recorder import record_hook_event
        sk_hex, signer_error = None, None
        if event in ("Stop", "SubagentStop", "SessionEnd"):
            sk_hex, signer_error = _signing_key(err, session_id=payload.get("session_id"),
                                                project=payload.get("cwd") or ".")
        receipt = record_hook_event(payload, signing_key_hex=sk_hex, signer_error=signer_error,
                                    guard_decision=decision.receipt_field() if decision else None)
    except Exception as exc:  # noqa: BLE001 -- a recorder must never break the session
        # The receipt is missing from the log; leave a trace where the operator will see it.
        print(f"perathos recorder: {type(exc).__name__}: {exc}", file=err)
        from .errlog import log_error
        log_error("claude-code.record", exc, session_id=payload.get("session_id"),
                  project=payload.get("cwd") or ".")

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
