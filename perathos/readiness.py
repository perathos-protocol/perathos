"""Readiness report: is this machine set up so the evidence will hold up?

`perathos doctor --recorder` runs these checks and prints PASS / WARN / FAIL for
each. FAIL means the evidence would be missing or unverifiable; WARN means it
works but a reviewer could reasonably push back (for example, the recorder key
also approves destructive actions). Exit code 1 if anything FAILs.

The checks only read files and run local verification; with `network=True`
the timestamp authority is also contacted.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
RECORD_STEMS = ("perathos-hook record", "perathos hooks record")


@dataclass
class Check:
    status: str
    area: str
    check: str
    detail: str


def _managed_settings_path() -> Path:
    if sys.platform.startswith("win"):
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ClaudeCode" / "managed-settings.json"
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    return Path("/etc/claude-code/managed-settings.json")


def _render(h: dict) -> str:
    cmd = str(h.get("command", ""))
    if isinstance(h.get("args"), list):
        stem = Path(cmd).name
        stem = stem[:-4] if stem.lower().endswith(".exe") else stem
        return " ".join([stem, *map(str, h["args"])])
    return cmd


def _hooks_in(settings: dict, event: str) -> list[dict]:
    out = []
    for entry in (settings.get("hooks") or {}).get(event) or []:
        if isinstance(entry, dict):
            for h in entry.get("hooks") or []:
                if isinstance(h, dict) and any(_render(h).startswith(s) for s in RECORD_STEMS):
                    out.append(h)
    return out


def _resolvable(h: dict) -> bool:
    cmd = str(h.get("command", ""))
    if isinstance(h.get("args"), list):
        return Path(cmd).is_file()
    exe = cmd.split()[0] if cmd else ""
    return bool(exe) and shutil.which(exe) is not None


def _read_json(p: Path) -> dict | None:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def run_checks(project: Path, *, network: bool = False, max_sessions: int = 5) -> list[Check]:
    from .approvers import get_config, list_approvers, local_verify_key, trusted_approver_keys
    from .signers import SignerError, configured_spec, signer_from_spec

    checks: list[Check] = []
    add = lambda s, a, c, d: checks.append(Check(s, a, c, d))  # noqa: E731

    # ---- keys ----
    spec = configured_spec()
    recorder_key = None
    try:
        import hashlib

        from .signing import sign_hash_with_signer, verify_signature
        signer = signer_from_spec(spec)
        h = hashlib.sha256(b"readiness").hexdigest()
        ok, err = verify_signature(h, sign_hash_with_signer(h, signer))
        recorder_key = signer.public_key.hex()
        add(PASS if ok else FAIL, "keys", "recorder signer works", f"{spec}: {recorder_key[:16]}..." if ok else err)
    except SignerError as exc:
        add(FAIL, "keys", "recorder signer works", f"{spec}: {exc}")
    if spec == "local":
        add(WARN, "keys", "recorder key kept off this machine",
            "the key file is on the same machine as the agent; use a remote signer "
            "(perathos config signer vault:... | gcpkms:... | command:...)")
    else:
        add(PASS, "keys", "recorder key kept off this machine", spec)

    listed = list_approvers()
    trusted = trusted_approver_keys() or set()
    if not trusted:
        add(FAIL, "keys", "safety-check approvers", "no approver key at all: every destructive action is denied")
    elif not listed:
        add(WARN, "keys", "safety-check approvers",
            "no approvers listed, so the recorder key also approves destructive actions; "
            "add a person's key held elsewhere: perathos approvers add --name <who> --signer <spec>")
    elif recorder_key and recorder_key in trusted:
        add(WARN, "keys", "safety-check approvers",
            f"{len(listed)} listed, but the recorder key is one of them, so whoever holds it can approve")
    else:
        add(PASS, "keys", "safety-check approvers", ", ".join(a["name"] for a in listed))
    if local_verify_key() is None and spec == "local":
        add(FAIL, "keys", "local key present", "run: perathos keygen")

    # ---- Claude Code hooks ----
    sources = [("managed", _managed_settings_path()),
               ("user", Path.home() / ".claude" / "settings.json"),
               ("project", project / ".claude" / "settings.json"),
               ("project-local", project / ".claude" / "settings.local.json")]
    found_any = False
    managed_locked = False
    for label, path in sources:
        settings = _read_json(path) if path.exists() else None
        if settings is None:
            continue
        events = {ev: _hooks_in(settings, ev) for ev in ("PreToolUse", "PostToolUse", "Stop", "SessionEnd")}
        if not any(events.values()):
            continue
        found_any = True
        if label == "managed" and settings.get("allowManagedHooksOnly") is True:
            managed_locked = True
        missing = [ev for ev, hs in events.items() if not hs]
        add(PASS if not missing else FAIL, "claude code", f"recorder hooks ({label})",
            f"{path}" if not missing else f"missing for {', '.join(missing)} in {path}")
        pre = events["PreToolUse"]
        guarded = [h for h in pre if "--guard" in _render(h)]
        add(PASS if guarded else WARN, "claude code", f"guard on ({label})",
            "PreToolUse runs --guard" if guarded else "PreToolUse has no --guard: destructive commands are recorded but not blocked")
        if guarded:
            fc = all(h.get("onFailure") == "block" for h in guarded)
            add(PASS if fc else WARN, "claude code", f"guard fails closed ({label})",
                'onFailure: "block"' if fc else "a missing or crashing guard lets the call through; reinstall with --force")
        unresolvable = [_render(h) for hs in events.values() for h in hs if not _resolvable(h)]
        add(PASS if not unresolvable else FAIL, "claude code", f"hook programs found ({label})",
            "all hook commands resolve" if not unresolvable else
            f"cannot find: {unresolvable[0]} (reinstall from the environment where perathos is installed)")
        anchored = any("--anchor" in _render(h) for h in events["Stop"])
        add(PASS if anchored else WARN, "timestamps", f"checkpoints timestamped ({label})",
            "Stop hook runs --anchor" if anchored else "no --anchor: times come from the local clock")
    if not found_any:
        add(FAIL, "claude code", "recorder hooks", "no perathos recorder hooks in managed, user or project settings")
    else:
        add(PASS if managed_locked else WARN, "claude code", "hooks locked against the agent",
            "managed settings with allowManagedHooksOnly" if managed_locked else
            "hooks are in user/project settings; the guard denies edits to them, but managed settings "
            "(perathos hooks install --scope managed) make edits impossible")

    # ---- Cursor ----
    cursor_cfg = _read_json(project / ".cursor" / "hooks.json")
    if cursor_cfg is not None:
        cmds = [str(e.get("command", "")) for evs in (cursor_cfg.get("hooks") or {}).values()
                for e in (evs or []) if isinstance(e, dict)]
        rec = [c for c in cmds if "record-cursor" in c]
        add(PASS if rec else WARN, "cursor", "recorder hooks", f"{len(rec)} perathos hook(s) in .cursor/hooks.json")
        guard_entries = [e for evs in (cursor_cfg.get("hooks") or {}).values() for e in (evs or [])
                         if isinstance(e, dict) and "--guard" in str(e.get("command", ""))]
        if guard_entries:
            fc = all(e.get("failClosed") is True for e in guard_entries)
            add(PASS if fc else WARN, "cursor", "guard fails closed", "failClosed: true" if fc else "set failClosed")

    # ---- timestamps ----
    try:
        import rfc3161_client  # noqa: F401
        add(PASS, "timestamps", "timestamp support installed", "rfc3161-client")
    except ImportError:
        add(WARN, "timestamps", "timestamp support installed", "pip install 'perathos[anchor]'")
    mirror = os.environ.get("PERATHOS_ANCHOR_MIRROR") or get_config().get("anchor_mirror")
    if mirror:
        mp = Path(mirror)
        ok = mp.exists() and os.access(mp, os.W_OK)
        add(PASS if ok else FAIL, "timestamps", "second copy of timestamps", f"{mirror}" + ("" if ok else " is not writable"))
    else:
        add(WARN, "timestamps", "second copy of timestamps",
            "no anchor mirror: a cut-off log is provable only while ~/.perathos/anchors is intact "
            "(perathos config anchor_mirror <folder the agent cannot reach>)")
    if network:
        try:
            from .anchor import anchor_checkpoint  # noqa: F401
            from .anchor import request_timestamp
            request_timestamp("00" * 32, timeout=8)
            add(PASS, "timestamps", "timestamp authority reachable", "freetsa.org")
        except Exception as exc:  # noqa: BLE001
            add(WARN, "timestamps", "timestamp authority reachable", str(exc)[:120])

    # ---- recent sessions verify ----
    from .recorder import verify_session
    sess_dir = project / ".perathos" / "sessions"
    logs = sorted(sess_dir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:max_sessions] \
        if sess_dir.exists() else []
    if not logs:
        add(INFO, "evidence", "recent sessions verify", "no session logs in this project yet")
    for log in logs:
        anchors = Path.home() / ".perathos" / "anchors" / f"{log.stem}.jsonl"
        try:
            rep = verify_session(log, expected_verify_key=recorder_key,
                                 anchors_path=anchors if anchors.exists() else None)
        except Exception as exc:  # noqa: BLE001
            add(FAIL, "evidence", f"session {log.stem[:12]}", f"could not verify: {exc}")
            continue
        detail = (f"{rep.tool_calls} calls, {rep.blocked} blocked, sealed through {rep.sealed_through}"
                  + (f", timestamped through {rep.anchored_through}" if rep.anchors else ""))
        add(PASS if rep.valid else FAIL, "evidence", f"session {log.stem[:12]}",
            detail if rep.valid else "; ".join(rep.errors[:2]))

    # ---- recording failures (a failed hook leaves no receipt, so only this local log shows it) ----
    from .errlog import errors_log_path, read_errors
    logged = read_errors()
    here = read_errors(project=project)
    if not logged:
        add(PASS, "evidence", "recording failures logged", f"none in {errors_log_path()}")
    else:
        last = logged[-1]
        add(WARN, "evidence", "recording failures logged",
            f"{len(logged)} in {errors_log_path()} ({len(here)} for this project); latest {last.get('ts')} "
            f"{last.get('component')}: {last.get('error')}. Receipts may be missing or checkpoints unsigned; "
            f"fix the cause, then delete the file to reset the count")

    # ---- preconditions ----
    from .guard import check_precondition, preconditions_dir
    pcd = preconditions_dir(project)
    if pcd.exists():
        valid = 0
        for f in pcd.glob("*.json"):
            pc = _read_json(f) or {}
            if check_precondition(pc, trusted_key=trusted) is None:
                valid += 1
        add(INFO, "guard", "active preconditions", f"{valid} valid now")
    return checks


def render_text(checks: list[Check]) -> str:
    width = max((len(c.check) for c in checks), default=10)
    lines = [f"{c.status:5} {c.area:12} {c.check:{width}}  {c.detail}" for c in checks]
    n = {s: sum(1 for c in checks if c.status == s) for s in (PASS, WARN, FAIL)}
    lines.append(f"\n{n[PASS]} pass, {n[WARN]} warn, {n[FAIL]} fail")
    return "\n".join(lines)


def render_markdown(checks: list[Check], project: Path) -> str:
    from . import __version__
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    out = ["# Perathos readiness report", "", f"Project: `{project}`  ", f"Generated: {now} by perathos {__version__}", "",
           "| Status | Area | Check | Detail |", "|---|---|---|---|"]
    out += [f"| {c.status} | {c.area} | {c.check} | {c.detail.replace('|', '/')} |" for c in checks]
    return "\n".join(out) + "\n"


def to_json(checks: list[Check]) -> str:
    return json.dumps([asdict(c) for c in checks], indent=2)
