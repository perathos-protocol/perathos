"""Cursor hooks -> perathos flight recorder (+ guard, checkpoints, anchors).

Cursor runs every command configured in ``hooks.json`` for an agent event,
passes the event as JSON on stdin and reads a JSON response from stdout. This
module turns those events into the same ``perathos.receipt/v1`` chain the
Claude Code integration writes (``perathos/recorder.py``), applies the
destructive-command guard (``perathos/guard.py``) to shell commands, MCP tool
calls and file reads, and answers Cursor in its own response format.

Sources (Cursor's official documentation, read 2026-11-04):
  * https://cursor.com/docs/agent/hooks  (the "Hooks" reference; its internal
    links point at https://cursor.com/docs/hooks.md)

What the docs establish, and what this module relies on:
  * Config: ``<project>/.cursor/hooks.json`` (project hooks, run from the
    project root) and ``~/.cursor/hooks.json`` (user hooks, run from
    ``~/.cursor/``); also enterprise files and team (dashboard) hooks. Shape::

        {"version": 1, "hooks": {"<eventName>": [{"command": "...", "timeout": 10}]}}

    Optional per-entry keys: ``type`` ("command" default | "prompt"),
    ``timeout`` (seconds), ``matcher`` (regex), ``failClosed`` (default
    false), ``loop_limit`` (stop/subagentStop).
  * Common stdin fields: ``conversation_id``, ``generation_id``, ``model``,
    ``hook_event_name``, ``cursor_version``, ``workspace_roots``,
    ``user_email``, ``transcript_path``.
  * Per-event stdin fields used here:
      - beforeShellExecution: ``command``, ``cwd``, ``sandbox``
      - afterShellExecution: ``command``, ``output``, ``duration``, ``sandbox``
      - beforeMCPExecution: ``tool_name``, ``tool_input`` (a JSON *string*),
        ``mcp_server_name``, ``url``/``mcp_server_url`` or ``command``
      - afterMCPExecution: ``tool_name``, ``tool_input``, ``mcp_server_name``,
        ``result_json`` (a JSON string), ``duration``
      - beforeReadFile: ``file_path``, ``content``, ``attachments``
      - afterFileEdit: ``file_path``, ``edits`` [{old_string, new_string}]
      - stop: ``status``, ``loop_count``
      - sessionEnd: ``session_id``, ``reason``, ``duration_ms``, ...
  * Responses: beforeShellExecution / beforeMCPExecution accept
    ``{"permission": "allow"|"deny"|"ask", "user_message", "agent_message",
    "continue"}``; beforeReadFile accepts ``{"permission": "allow"|"deny",
    "user_message"}``. For these permission hooks, invalid JSON or a response
    that does not match the schema *blocks* the action, even with exit 0, so
    this module always prints a valid response for them.
  * Exit codes: 0 = use the JSON on stdout; 2 = block (same as deny); any
    other code = hook failure, the action proceeds unless ``failClosed``.
    We always exit 0 and deny through the JSON ``permission`` field.

Defensive choices (not pinned down by the docs):
  * ``workspace_roots`` is documented only as "absolute path"; ``file://``
    URIs and ``/c:/...``-style Windows paths are normalised too.
  * The session id is ``conversation_id``, falling back to ``session_id``
    (sessionEnd) and then ``generation_id``.
  * ``tool_input`` / ``result_json`` are documented as strings; objects are
    accepted as well. MCP arguments are parsed before hashing so the before
    and after events hash identically regardless of whitespace.
  * Cursor gives shell/MCP events no tool-call id, so ``tool_use_id`` is
    derived from ``generation_id`` + the argument hash, which links each
    before event to its after event.
  * If afterShellExecution carries no ``output`` (or afterMCPExecution no
    ``result_json``), the result hash is taken over the payload minus
    volatile fields and the receipt is marked ``"result_from": "payload"``.

Mapping onto receipts (``agent`` = "cursor"):
  * beforeShellExecution -> ``pre`` (tool "Bash", args = the command), guarded
    as ``Bash {"command": ...}``.
  * beforeMCPExecution -> ``pre`` (tool ``mcp__<server>__<tool>``, the same
    naming Claude Code uses, so the guard's destructive-MCP-tool rule applies).
  * afterShellExecution / afterMCPExecution -> ``post`` with ``result_hash``.
  * afterFileEdit -> a ``pre`` + ``post`` pair for tool "Edit", written back
    to back (Cursor only reports edits after they happen, so this ``pre`` is
    not a record of intent; it keeps edits counted as tool calls).
  * beforeReadFile (installed only with ``--guard``) -> no receipt for an
    ordinary read; a ``pre`` receipt with the guard decision when a rule
    matches (reading the perathos signing key).
  * stop / sessionEnd / subagentStop -> signed ``checkpoint``; ``model`` is
    Cursor's self-reported ``model`` field.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from ..recorder import append_receipt, content_hash, safe_session_id, session_log_path

AGENT_CURSOR = "cursor"
RECORD_CURSOR_CMD = "perathos hooks record-cursor"

SHELL_BEFORE = "beforeShellExecution"
SHELL_AFTER = "afterShellExecution"
MCP_BEFORE = "beforeMCPExecution"
MCP_AFTER = "afterMCPExecution"
READ_BEFORE = "beforeReadFile"
FILE_EDIT = "afterFileEdit"
CHECKPOINT_EVENTS = ("stop", "sessionEnd", "subagentStop")
PERMISSION_EVENTS = (SHELL_BEFORE, MCP_BEFORE, READ_BEFORE)

# Fields that change between otherwise identical events; excluded when a
# result has to be hashed from the payload itself.
_VOLATILE = {
    "conversation_id", "generation_id", "hook_event_name", "cursor_version", "user_email",
    "transcript_path", "model", "model_id", "model_params", "workspace_roots", "duration",
    "duration_ms", "session_id",
}
_WIN_DRIVE_URI = re.compile(r"^/[A-Za-z]:[/\\]")


# --------------------------------------------------------------------------- #
# Payload helpers
# --------------------------------------------------------------------------- #

def _norm_path(p: Any) -> str | None:
    if not isinstance(p, str) or not p.strip():
        return None
    p = p.strip()
    if p.startswith("file://"):
        p = unquote(urlparse(p).path)
    if _WIN_DRIVE_URI.match(p):
        p = p[1:]
    return p


def workspace_root(payload: dict[str, Any]) -> str:
    """Directory that holds ``.perathos/``: the same for every event of a session.

    ``stop`` carries no ``cwd``, and a shell ``cwd`` can be a subdirectory,
    so the first workspace root wins, then ``CURSOR_PROJECT_DIR``, then cwd.
    """
    roots = payload.get("workspace_roots")
    if isinstance(roots, str):
        roots = [roots]
    if isinstance(roots, list):
        for r in roots:
            if (n := _norm_path(r)) is not None:
                return n
    for cand in (os.environ.get("CURSOR_PROJECT_DIR"), payload.get("cwd")):
        if (n := _norm_path(cand)) is not None:
            return n
    return "."


def session_id(payload: dict[str, Any]) -> str:
    for key in ("conversation_id", "session_id", "generation_id"):
        if payload.get(key):
            return safe_session_id(payload[key])
    return safe_session_id(None)


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _mcp_tool(payload: dict[str, Any]) -> str:
    name = str(payload.get("tool_name") or "")
    if name.startswith("mcp__"):
        return name
    server = str(payload.get("mcp_server_name") or payload.get("server_name") or "").strip()
    return f"mcp__{server}__{name}" if server else f"mcp__{name}"


def _call_id(payload: dict[str, Any], args_hash: str) -> str:
    gen = payload.get("generation_id") or payload.get("conversation_id") or "cursor"
    return f"{gen}:{args_hash[:16]}"


def _payload_result(payload: dict[str, Any]) -> str:
    return content_hash({k: v for k, v in payload.items() if k not in _VOLATILE})


# --------------------------------------------------------------------------- #
# Recording
# --------------------------------------------------------------------------- #

def guard_target(payload: dict[str, Any]) -> tuple[str, Any] | None:
    """(tool_name, tool_input) to hand to ``guard.decide`` for a permission event."""
    event = payload.get("hook_event_name")
    if event == SHELL_BEFORE:
        return "Bash", {"command": str(payload.get("command") or "")}
    if event == MCP_BEFORE:
        return _mcp_tool(payload), _maybe_json(payload.get("tool_input"))
    if event == READ_BEFORE:
        return "Read", {"file_path": str(payload.get("file_path") or "")}
    return None


def record_cursor_event(
    payload: dict[str, Any],
    *,
    signing_key_hex: str | None = None,
    guard_decision: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Append the receipts for one Cursor hook event; returns them (maybe empty)."""
    event = payload.get("hook_event_name")
    root = workspace_root(payload)
    sid = session_id(payload)
    log_path = session_log_path(root, sid)
    base = {"session_id": sid, "agent": AGENT_CURSOR}

    def pre(tool: str, args: Any) -> dict[str, Any]:
        ah = content_hash(args)
        fields: dict[str, Any] = {**base, "kind": "pre", "tool": tool,
                                  "tool_use_id": _call_id(payload, ah), "args_hash": ah}
        if guard_decision is not None:
            fields["guard"] = guard_decision
        return append_receipt(log_path, fields)

    def post(tool: str, args: Any, result_field: str) -> dict[str, Any]:
        ah = content_hash(args)
        fields: dict[str, Any] = {**base, "kind": "post", "tool": tool,
                                  "tool_use_id": _call_id(payload, ah), "args_hash": ah}
        if result_field in payload:
            fields["result_hash"] = content_hash(payload.get(result_field))
        else:
            fields["result_hash"] = _payload_result(payload)
            fields["result_from"] = "payload"
        fields["status"] = "ok"
        return append_receipt(log_path, fields)

    if event == SHELL_BEFORE:
        return [pre("Bash", str(payload.get("command") or ""))]
    if event == SHELL_AFTER:
        return [post("Bash", str(payload.get("command") or ""), "output")]
    if event == MCP_BEFORE:
        return [pre(_mcp_tool(payload), _maybe_json(payload.get("tool_input")))]
    if event == MCP_AFTER:
        return [post(_mcp_tool(payload), _maybe_json(payload.get("tool_input")), "result_json")]
    if event == READ_BEFORE:
        # Ordinary reads are not recorded (Cursor fires this for every file the
        # agent reads); only a guard match leaves a trace.
        if guard_decision is None:
            return []
        return [pre("Read", {"file_path": str(payload.get("file_path") or "")})]
    if event == FILE_EDIT:
        args = {"file_path": str(payload.get("file_path") or ""), "edits": payload.get("edits")}
        ah = content_hash(args)
        tuid = _call_id(payload, ah)
        p = append_receipt(log_path, {**base, "kind": "pre", "tool": "Edit", "tool_use_id": tuid,
                                      "args_hash": ah})
        q = append_receipt(log_path, {**base, "kind": "post", "tool": "Edit", "tool_use_id": tuid,
                                      "args_hash": ah, "result_hash": content_hash(payload.get("edits")),
                                      "status": "ok"})
        return [p, q]
    if event in CHECKPOINT_EVENTS:
        model = payload.get("model")
        fields = {**base, "kind": "checkpoint", "event": event,
                  "model": model if isinstance(model, str) and model else None}
        return [append_receipt(log_path, fields, signing_key_hex=signing_key_hex)]
    return []


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #

def cursor_response(event: Any, decision: Any = None) -> dict[str, Any]:
    """The JSON Cursor expects on stdout for this event.

    ``decision`` is a ``guard.Decision`` (or None). Only fields documented for
    each event are emitted: an unexpected field in a permission hook's
    response can make Cursor block the action.
    """
    deny = decision is not None and getattr(decision, "decision", None) == "deny"
    if event in (SHELL_BEFORE, MCP_BEFORE):
        if deny:
            return {"continue": True, "permission": "deny",
                    "user_message": decision.reason,
                    "agent_message": decision.reason}
        return {"continue": True, "permission": "allow"}
    if event == READ_BEFORE:
        if deny:
            return {"permission": "deny", "user_message": decision.reason}
        return {"permission": "allow"}
    if event in PERMISSION_EVENTS or not isinstance(event, str):
        return {"permission": "allow"}
    return {}


def run_hook(
    raw: str,
    *,
    guard: bool = False,
    anchor: bool = False,
    load_signing_key: Callable[[], str] | None = None,
    verify_key: Callable[[], str | None] | None = None,
    warn: Callable[[str], None] = lambda msg: None,
) -> dict[str, Any]:
    """Handle one Cursor hook invocation; returns the stdout response. Never raises.

    Malformed stdin yields ``{"permission": "allow"}`` (valid for every
    permission hook, ignored by the others). A guard deny is returned even if
    writing the receipt fails: the guard fails closed. A crash inside the
    guard itself fails open (allow) and is reported on stderr, as the Claude
    Code hook does.
    """
    try:
        payload = json.loads(raw or "{}")
    except (ValueError, TypeError):
        warn("perathos cursor: stdin is not JSON; allowing")
        return {"permission": "allow"}
    if not isinstance(payload, dict):
        return {"permission": "allow"}
    event = payload.get("hook_event_name")

    decision = None
    if guard:
        try:
            target = guard_target(payload)
            if target is not None:
                from ..guard import decide

                decision = decide(target[0], target[1], workspace_root(payload),
                                  trusted_key=verify_key() if verify_key else None)
        except Exception as exc:  # noqa: BLE001
            # Fail closed: a guard that crashes cannot clear the call, so deny it.
            from ..guard import Decision
            warn(f"perathos guard: {type(exc).__name__}: {exc}")
            decision = Decision("deny", "guard.error", None, f"perathos guard: blocked because the guard itself failed ({type(exc).__name__}: {exc}). The guard fails closed; fix the error or remove --guard.")

    receipts: list[dict[str, Any]] = []
    try:
        sk_hex = None
        if event in CHECKPOINT_EVENTS and load_signing_key is not None:
            try:
                sk_hex = load_signing_key()
            except (FileNotFoundError, ValueError):
                sk_hex = None
        receipts = record_cursor_event(payload, signing_key_hex=sk_hex,
                                       guard_decision=decision.receipt_field() if decision else None)
    except Exception as exc:  # noqa: BLE001 -- a recorder must never break the session
        warn(f"perathos recorder: {type(exc).__name__}: {exc}")

    if anchor:
        for rec in receipts:
            if rec.get("kind") == "checkpoint" and rec.get("signature"):
                try:
                    from ..anchor import anchor_checkpoint, default_anchors_path

                    anchor_checkpoint(rec, default_anchors_path(rec["session_id"]), timeout=8)
                except Exception as exc:  # noqa: BLE001 -- the TSA may be down; never fail the turn
                    warn(f"perathos anchor: {type(exc).__name__}: {exc} (run 'perathos session anchor' later)")

    return cursor_response(event, decision)


# --------------------------------------------------------------------------- #
# Installing into hooks.json
# --------------------------------------------------------------------------- #

class HookConfigError(Exception):
    """hooks.json cannot be updated (invalid JSON, or perathos already there without --force)."""


def hooks_json_path(scope: str) -> Path:
    if scope == "user":
        return Path.home() / ".cursor" / "hooks.json"
    return Path(".cursor") / "hooks.json"


def _is_perathos_cursor_entry(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    cmd = str(entry.get("command") or "")
    return cmd == RECORD_CURSOR_CMD or cmd.startswith(RECORD_CURSOR_CMD + " ")


def planned_hooks(*, guard: bool, anchor: bool) -> dict[str, str]:
    """{event: command} that ``install`` writes."""
    g = " --guard" if guard else ""
    a = " --anchor" if anchor else ""
    plan = {
        SHELL_BEFORE: RECORD_CURSOR_CMD + g,
        SHELL_AFTER: RECORD_CURSOR_CMD,
        MCP_BEFORE: RECORD_CURSOR_CMD + g,
        MCP_AFTER: RECORD_CURSOR_CMD,
        FILE_EDIT: RECORD_CURSOR_CMD,
        "stop": RECORD_CURSOR_CMD + a,
        "sessionEnd": RECORD_CURSOR_CMD + a,
    }
    if guard:
        plan[READ_BEFORE] = RECORD_CURSOR_CMD + g
    return plan


def install(path: Path, *, guard: bool = False, anchor: bool = False, force: bool = False) -> dict[str, Any]:
    """Add the perathos entries to a Cursor hooks.json, keeping everything else.

    Raises ``HookConfigError`` if the file is not a JSON object, or if a
    perathos entry already exists and ``force`` is False. With ``force``
    every existing perathos entry (in any event) is replaced.
    """
    config: dict[str, Any] = {}
    if path.exists():
        try:
            config = json.loads(path.read_text(encoding="utf-8") or "{}")
        except ValueError as exc:
            raise HookConfigError(f"{path} is not valid JSON: {exc}") from exc
        if not isinstance(config, dict):
            raise HookConfigError(f"{path} does not contain a JSON object")
    hooks = config.get("hooks")
    if hooks is None:
        hooks = config["hooks"] = {}
    if not isinstance(hooks, dict):
        raise HookConfigError(f"{path}: 'hooks' is not an object")
    config.setdefault("version", 1)

    already = [ev for ev, entries in hooks.items()
               if isinstance(entries, list) and any(_is_perathos_cursor_entry(e) for e in entries)]
    if already and not force:
        raise HookConfigError(f"perathos hooks are already installed in {path} ({', '.join(already)}); "
                              f"use --force to reinstall")
    for ev in already:
        hooks[ev] = [e for e in hooks[ev] if not _is_perathos_cursor_entry(e)]
        if not hooks[ev]:
            del hooks[ev]

    for ev, cmd in planned_hooks(guard=guard, anchor=anchor).items():
        entries = hooks.setdefault(ev, [])
        if not isinstance(entries, list):
            raise HookConfigError(f"{path}: hooks.{ev} is not a list")
        entry = {"command": cmd, "timeout": 20 if "--anchor" in cmd else 10}
        if "--guard" in cmd:
            entry["failClosed"] = True  # a missing or crashing guard blocks the action
        entries.append(entry)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return config
