"""Recording proxy for any MCP server (stdio transport).

Put ``perathos mcp-proxy`` in front of an MCP server in any MCP client's
configuration (Claude Desktop, Claude Code, Cursor, Windsurf, custom agents):

    perathos mcp-proxy --name postgres --guard -- npx -y @modelcontextprotocol/server-postgres postgresql://...

The proxy starts the real server, relays every JSON-RPC message unchanged in
both directions, and for each ``tools/call``:

* writes a ``pre`` receipt (tool ``mcp__<name>__<tool>``, hash of the
  arguments) and, with ``--guard``, applies the destructive-action guard to the
  tool name *and* to every string argument (so ``execute_sql`` carrying
  ``DROP TABLE`` is caught). A denied call never reaches the server: the
  client gets a normal tool result with ``isError: true`` explaining why.
* writes a ``post`` receipt when the server answers (hash of the result;
  status ``error`` for JSON-RPC errors or ``isError`` results).

A signed checkpoint seals the log every ``--seal-every`` tool calls and when
the session ends (client disconnects or the server exits), optionally with an
RFC 3161 timestamp (``--anchor``). Receipts use the same format and verifier
as the Claude Code hooks: ``perathos session verify <session id>``.

MCP's stdio transport sends one JSON-RPC message per line (no embedded
newlines), which is what this proxy relies on. Lines it cannot parse are
relayed untouched and not recorded.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from .recorder import append_receipt, content_hash, safe_session_id, session_log_path

# Same receipt format as the Claude Code hooks; only the `agent` field differs.
AGENT_MCP_PROXY = "mcp-proxy"


class McpRecorder:
    def __init__(self, *, name: str, project: Path, session_id: str | None = None,
                 guard: bool = False, signing_key_hex: str | None = None, trusted_key: str | None = None,
                 anchor: bool = False, seal_every: int = 20):
        self.name = safe_session_id(name)
        self.project = project
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.session_id = safe_session_id(session_id or f"mcp-{self.name}-{stamp}")
        self.log = session_log_path(project, self.session_id)
        self.guard = guard
        self.sk = signing_key_hex
        self.trusted_key = trusted_key
        self.anchor = anchor
        self.seal_every = max(1, seal_every)
        self.pending: dict[Any, tuple[str, Any]] = {}  # json-rpc id -> (tool, args)
        self.calls_since_seal = 0
        self.lock = threading.Lock()
        self.errors: list[str] = []

    def _base(self) -> dict[str, Any]:
        return {"session_id": self.session_id, "agent": AGENT_MCP_PROXY}

    def tool_name(self, raw: str) -> str:
        return f"mcp__{self.name}__{raw}"

    # client -> server
    def on_tools_call(self, msg: dict) -> dict | None:
        """Record a tools/call. Returns a JSON-RPC response to send back instead
        of forwarding (guard deny), or None to forward the request."""
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = self.tool_name(str(params.get("name") or ""))
        args = params.get("arguments")
        decision = None
        if self.guard:
            try:
                from .guard import decide
                decision = decide(tool, args if isinstance(args, dict) else {"arguments": args},
                                  self.project, trusted_key=self.trusted_key)
                if decision is not None and decision.decision == "deny":
                    from .gate import apply_gate
                    decision = apply_gate(decision, tool=tool, args=args if isinstance(args, dict) else {"arguments": args},
                                          cwd=self.project, session_id=self.session_id, agent_name="mcp-proxy",
                                          wait_seconds=0)
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"guard: {exc}")
        fields = {**self._base(), "kind": "pre", "tool": tool, "tool_use_id": _id_str(msg.get("id")),
                  "args_hash": content_hash(args)}
        if decision is not None:
            fields["guard"] = decision.receipt_field()
        try:
            with self.lock:
                append_receipt(self.log, fields)
                if not (decision and decision.decision == "deny"):
                    self.pending[_id_key(msg.get("id"))] = (tool, args)
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"record: {exc}")
        if decision is not None and decision.decision == "deny":
            return {"jsonrpc": "2.0", "id": msg.get("id"), "result": {
                "content": [{"type": "text", "text": decision.reason}], "isError": True}}
        return None

    # server -> client
    def on_response(self, msg: dict) -> None:
        key = _id_key(msg.get("id"))
        with self.lock:
            entry = self.pending.pop(key, None)
        if entry is None:
            return
        tool, args = entry
        if "error" in msg:
            result, status = msg.get("error"), "error"
        else:
            result = msg.get("result")
            status = "error" if isinstance(result, dict) and result.get("isError") else "ok"
        try:
            with self.lock:
                append_receipt(self.log, {**self._base(), "kind": "post", "tool": tool,
                                          "tool_use_id": _id_str(msg.get("id")), "args_hash": content_hash(args),
                                          "result_hash": content_hash(result), "status": status})
                self.calls_since_seal += 1
                due = self.calls_since_seal >= self.seal_every
            if due:
                self.seal("periodic")
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"record: {exc}")

    def seal(self, event: str) -> dict | None:
        """Append a signed checkpoint (and anchor it if asked)."""
        if not self.log.exists():
            return None
        with self.lock:
            cp = append_receipt(self.log, {**self._base(), "kind": "checkpoint", "event": f"mcp-{event}",
                                           "model": None}, signing_key_hex=self.sk)
            self.calls_since_seal = 0
        if self.anchor and cp.get("signature"):
            try:
                from .anchor import anchor_checkpoint, default_anchors_path
                anchor_checkpoint(cp, default_anchors_path(self.session_id), timeout=8)
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"anchor: {exc}")
        return cp


def _id_key(rid: Any) -> str:
    return json.dumps(rid, sort_keys=True)


def _id_str(rid: Any) -> str | None:
    return None if rid is None else str(rid)


def _parse(line: bytes) -> dict | list | None:
    """One JSON-RPC message, or a batch (list) of them, or None."""
    try:
        msg = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        return None
    return msg if isinstance(msg, (dict, list)) else None


def _as_list(msg: dict | list | None) -> list[dict]:
    if isinstance(msg, dict):
        return [msg]
    if isinstance(msg, list):
        return [m for m in msg if isinstance(m, dict)]
    return []


def run_proxy(server_cmd: list[str], rec: McpRecorder, *, stdin: BinaryIO | None = None,
              stdout: BinaryIO | None = None, stderr=None) -> int:
    """Relay stdio between the client (our stdin/stdout) and the server."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=stderr if stderr is not None else sys.stderr)
    out_lock = threading.Lock()

    def to_client(data: bytes) -> None:
        with out_lock:
            stdout.write(data)
            stdout.flush()

    def server_to_client() -> None:
        assert proc.stdout is not None
        for line in iter(proc.stdout.readline, b""):
            for msg in _as_list(_parse(line)):
                if "id" in msg and ("result" in msg or "error" in msg):
                    rec.on_response(msg)
            to_client(line)

    pump = threading.Thread(target=server_to_client, daemon=True)
    pump.start()
    try:
        assert proc.stdin is not None
        for line in iter(stdin.readline, b""):
            parsed = _parse(line)
            msgs = _as_list(parsed)
            denied: list[dict] = []
            forward: list[dict] = []
            for msg in msgs:
                reply = None
                if msg.get("method") == "tools/call" and "id" in msg:
                    reply = rec.on_tools_call(msg)
                (denied if reply is not None else forward).append(reply if reply is not None else msg)
            if isinstance(parsed, list):
                # Batch: answer denied calls ourselves, forward the rest as a batch.
                if denied:
                    to_client((json.dumps(denied) + "\n").encode("utf-8"))
                if not forward:
                    continue
                line = (json.dumps(forward) + "\n").encode("utf-8")
            elif denied:
                to_client((json.dumps(denied[0]) + "\n").encode("utf-8"))
                continue
            try:
                proc.stdin.write(line if line.endswith(b"\n") else line + b"\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                break
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        deadline = time.monotonic() + 5
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if proc.poll() is None:
            proc.terminate()
        pump.join(timeout=5)
        try:
            rec.seal("end")
        except Exception as exc:  # noqa: BLE001
            rec.errors.append(f"seal: {exc}")
        for e in rec.errors:
            print(f"perathos mcp-proxy: {e}", file=sys.stderr)
    return proc.returncode or 0


def env_project_dir() -> Path:
    return Path(os.environ.get("PERATHOS_PROJECT_DIR") or os.getcwd())
