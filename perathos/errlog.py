"""Local log of recording failures: ``~/.perathos/errors.log``.

The recorder never blocks an agent: when a hook cannot write a receipt, or the
configured signer cannot seal a checkpoint, the tool call still proceeds. That
leaves a gap in the session log which the log itself cannot show. Each such
failure appends one JSON line here (time, component, exception type, session,
project), and ``perathos doctor --recorder`` and ``perathos session verify``
report the count.

Honest limits: this file is local, unsigned, and writable by the same user as
the agent, so it is a diagnostic aid for the operator, not evidence. A failure
that also prevents writing this file (for example a full disk) is still only
visible on stderr. Standard library only: hooks import it on the error path.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

_MAX_BYTES = 1 << 20  # roll over to errors.log.1 past 1 MiB so the file stays small


def errors_log_path() -> Path:
    return Path(os.environ.get("PERATHOS_ERROR_LOG") or Path.home() / ".perathos" / "errors.log")


def log_error(component: str, exc: BaseException | str, *, session_id=None, project=None) -> None:
    """Append one line. Never raises: this runs inside handlers that must not fail."""
    try:
        path = errors_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if path.stat().st_size > _MAX_BYTES:
                os.replace(path, path.with_name(path.name + ".1"))
        except OSError:
            pass
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "component": component,
            "error": exc if isinstance(exc, str) else type(exc).__name__,
            "detail": "" if isinstance(exc, str) else str(exc)[:200],
            "session_id": str(session_id) if session_id else None,
            "project": str(Path(project).resolve()) if project else None,
        }
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception:  # noqa: BLE001, S110 -- the error log must never break the hook
        pass


def read_errors(*, session_id=None, project=None) -> list[dict]:
    """Logged failures (current file only), optionally for one session or project."""
    try:
        lines = errors_log_path().read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return []
    want_project = str(Path(project).resolve()) if project else None
    out = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict):
            continue
        if session_id is not None and entry.get("session_id") != str(session_id):
            continue
        if want_project is not None and entry.get("project") != want_project:
            continue
        out.append(entry)
    return out
