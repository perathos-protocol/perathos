"""Evidence packs: everything a third party needs to check an agent session.

``export_evidence_pack`` gathers, for one flight-recorder session:

* ``session.jsonl``      the hash-chained receipt log (and ``session.head.json``)
* ``anchors.jsonl``      independent RFC 3161 timestamps, if any
* ``preconditions/``     the signed safety checks the guard relied on
* ``verification.json``  the machine-readable result of ``verify_session``
* ``REPORT.md`` / ``REPORT.html``  a one-page human summary
* ``VERIFY.md``          how to re-check the pack independently
* ``MANIFEST.json``      SHA-256 of every file, signed with the local key

``verify_evidence_pack`` re-checks the manifest (every file present and
unmodified, signature valid) and then re-runs session verification from the
pack's own copies, so a recipient never has to trust the exporter's report.

What a pack does not contain: tool arguments or outputs (only their hashes).
Whoever holds the originals can show they match.
"""
from __future__ import annotations

import hashlib
import html
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes

MANIFEST_VERSION = "perathos.evidence/v1"
_LIMITS = [
    "Shows which key sealed the record, not which model ran (the model name is self-reported).",
    "Event times come from the local clock; only anchored checkpoints have an independent time.",
    "Tool arguments and outputs are not included, only their SHA-256 hashes.",
    "A gap in recording (hooks switched off) is not visible in the log.",
    "The guard matches command patterns; it is a safeguard against accidents, not a sandbox.",
]


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_receipts(log: Path) -> list[dict]:
    out = []
    for line in log.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    return out


def _project_root_for(log: Path) -> Path:
    # <root>/.perathos/sessions/<sid>.jsonl
    return log.parent.parent.parent


def _summarise(receipts: list[dict], preconditions: dict[str, dict]) -> dict[str, Any]:
    blocked, allowed = [], []
    for r in receipts:
        g = r.get("guard")
        if r.get("kind") == "pre" and isinstance(g, dict):
            item = {"seq": r.get("seq"), "ts": r.get("ts"), "tool": r.get("tool"), "rule": g.get("rule")}
            if g.get("decision") == "deny":
                blocked.append(item)
            else:
                pc = preconditions.get(str(g.get("precondition")))
                item["precondition"] = {
                    "id": pc.get("id"), "scope": pc.get("scope"), "check": pc.get("check"),
                    "manual_reason": pc.get("manual_reason"), "created": pc.get("created"),
                    "expires": pc.get("expires"),
                } if pc else {"hash": g.get("precondition"), "missing": True}
                allowed.append(item)
    return {"blocked_calls": blocked, "allowed_under_precondition": allowed}


def export_evidence_pack(
    log_path: str | Path,
    out_dir: str | Path,
    *,
    anchors_path: str | Path | None = None,
    expected_verify_key: str | None = None,
    tsa_roots=None,
    signing_key_hex: str | None = None,
    make_zip: bool = True,
) -> dict[str, Any]:
    """Build an evidence pack directory (and optionally a .zip next to it).

    Returns {"dir": path, "zip": path or None, "valid": bool, "report": dict}.
    The pack is written even when verification fails: an invalid log is
    itself evidence, and the report says exactly what failed.
    """
    from .recorder import head_path_for, verify_session

    log = Path(log_path)
    out = Path(out_dir)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    shutil.copyfile(log, out / "session.jsonl")
    head = head_path_for(log)
    if head.exists():
        shutil.copyfile(head, out / "session.head.json")
    if anchors_path and Path(anchors_path).exists():
        shutil.copyfile(anchors_path, out / "anchors.jsonl")

    receipts = _read_receipts(log)
    used = {str(r["guard"]["precondition"]) for r in receipts
            if r.get("kind") == "pre" and isinstance(r.get("guard"), dict) and r["guard"].get("precondition")}
    preconditions: dict[str, dict] = {}
    pc_dir = _project_root_for(log) / ".perathos" / "preconditions"
    if used and pc_dir.exists():
        (out / "preconditions").mkdir()
        for f in pc_dir.glob("*.json"):
            try:
                pc = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(pc, dict) and str(pc.get("precondition_hash")) in used:
                shutil.copyfile(f, out / "preconditions" / f.name)
                preconditions[str(pc["precondition_hash"])] = pc

    report = verify_session(
        out / "session.jsonl",
        expected_verify_key=expected_verify_key,
        anchors_path=(out / "anchors.jsonl") if (out / "anchors.jsonl").exists() else None,
        tsa_roots=tsa_roots,
        check_head=True,
    )
    summary = _summarise(receipts, preconditions)
    missing = [a["precondition"]["hash"] for a in summary["allowed_under_precondition"]
               if a["precondition"].get("missing")]
    verification = {**report.to_dict(), "path": "session.jsonl", **summary,
                    "preconditions_missing_from_pack": missing,
                    "limits": _LIMITS,
                    "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")}
    (out / "verification.json").write_text(json.dumps(verification, indent=2), encoding="utf-8")
    (out / "REPORT.md").write_text(_report_md(verification), encoding="utf-8")
    (out / "REPORT.html").write_text(_report_html(verification), encoding="utf-8")
    (out / "VERIFY.md").write_text(_verify_md(verification), encoding="utf-8")

    files = {}
    for f in sorted(out.rglob("*")):
        if f.is_file():
            files[f.relative_to(out).as_posix()] = _sha256_file(f)
    manifest: dict[str, Any] = {"v": MANIFEST_VERSION, "session_id": report.session_id, "files": files}
    manifest["manifest_hash"] = hashlib.sha256(canonical_bytes({k: v for k, v in manifest.items()})).hexdigest()
    if signing_key_hex:
        from .signing import sign_hash
        manifest["signature"] = sign_hash(manifest["manifest_hash"], signing_key_hex)
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    zip_path = None
    if make_zip:
        zip_path = out.with_suffix(".zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(out.rglob("*")):
                if f.is_file():
                    z.write(f, f"{out.name}/{f.relative_to(out).as_posix()}")
    return {"dir": out, "zip": zip_path, "valid": report.valid, "report": verification}


def verify_evidence_pack(pack: str | Path, *, expected_verify_key: str | None = None, tsa_roots=None) -> dict[str, Any]:
    """Re-check a pack from its own files. Accepts a directory or a .zip."""
    import tempfile

    from .recorder import verify_session
    from .signing import verify_signature

    pack = Path(pack)
    tmp = None
    if pack.suffix == ".zip":
        tmp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(pack) as z:
            for name in z.namelist():
                target = (Path(tmp.name) / name).resolve()
                if not str(target).startswith(str(Path(tmp.name).resolve())):
                    raise ValueError(f"unsafe path in zip: {name}")
            z.extractall(tmp.name)
        dirs = [p for p in Path(tmp.name).iterdir() if p.is_dir()]
        pack = dirs[0] if len(dirs) == 1 else Path(tmp.name)
    try:
        errors: list[str] = []
        manifest = json.loads((pack / "MANIFEST.json").read_text(encoding="utf-8"))
        body = {k: v for k, v in manifest.items() if k not in ("manifest_hash", "signature")}
        if hashlib.sha256(canonical_bytes(body)).hexdigest() != manifest.get("manifest_hash"):
            errors.append("ERR_MANIFEST_HASH: manifest was modified")
        sig = manifest.get("signature")
        if sig is None:
            errors.append("ERR_MANIFEST_UNSIGNED: the pack manifest is not signed")
        else:
            ok, err = verify_signature(str(manifest.get("manifest_hash")), sig)
            if not ok:
                errors.append(f"{err}: manifest signature")
            elif expected_verify_key and sig.get("verify_key") != expected_verify_key:
                errors.append("ERR_UNEXPECTED_SIGNER: manifest signed by a different key")
        listed = manifest.get("files", {})
        present = {f.relative_to(pack).as_posix() for f in pack.rglob("*") if f.is_file()} - {"MANIFEST.json"}
        for name, digest in listed.items():
            f = pack / name
            if not f.exists():
                errors.append(f"ERR_MISSING_FILE: {name}")
            elif _sha256_file(f) != digest:
                errors.append(f"ERR_FILE_MODIFIED: {name}")
        for extra in sorted(present - set(listed)):
            errors.append(f"ERR_UNLISTED_FILE: {extra}")
        anchors = pack / "anchors.jsonl"
        rep = verify_session(pack / "session.jsonl", expected_verify_key=expected_verify_key,
                             anchors_path=anchors if anchors.exists() else None, tsa_roots=tsa_roots,
                             check_head=False)
        head = pack / "session.head.json"
        if head.exists():
            h = json.loads(head.read_text(encoding="utf-8"))
            if h.get("seq") is not None and int(h["seq"]) > rep.sealed_through:
                rep.fail(f"ERR_TRUNCATED: head witness records seq {h['seq']}, log sealed through {rep.sealed_through}")
        errors.extend(rep.errors)
        return {"valid": not errors, "errors": errors, "session": rep.to_dict()}
    finally:
        if tmp is not None:
            tmp.cleanup()


# --------------------------------------------------------------------------- #
# Human-readable report
# --------------------------------------------------------------------------- #

def _report_md(v: dict) -> str:
    status = "VALID" if v["valid"] else "INVALID"
    lines = [
        f"# Agent session evidence: {v.get('session_id')}",
        "",
        f"**Verification: {status}**",
        "",
        f"- Recorded: {v.get('first_ts')} to {v.get('last_ts')} (local clock)",
        f"- Tool calls: {v.get('tool_calls')}, blocked by the guard: {v.get('blocked')}",
        f"- Sealed through receipt {v.get('sealed_through')} by {v.get('signed_checkpoints')} signed checkpoint(s)",
        f"- Signer key: {', '.join(v.get('signers') or []) or 'none'}",
        f"- Independent timestamps: {v.get('anchors')} (through receipt {v.get('anchored_through')}, "
        f"{v.get('anchored_time') or 'n/a'})",
        f"- Model (self-reported): {', '.join(v.get('models') or []) or 'unknown'}",
        "",
    ]
    if v.get("errors"):
        lines += ["## Verification failures", ""] + [f"- {e}" for e in v["errors"]] + [""]
    if v.get("blocked_calls"):
        lines += ["## Destructive calls blocked", ""]
        lines += [f"- receipt {b['seq']} at {b['ts']}: {b['tool']} matched `{b['rule']}`" for b in v["blocked_calls"]] + [""]
    if v.get("allowed_under_precondition"):
        lines += ["## Destructive calls allowed under a signed safety check", ""]
        for a in v["allowed_under_precondition"]:
            pc = a["precondition"]
            what = pc.get("check") or pc.get("manual_reason") or "(precondition missing from pack)"
            lines.append(f"- receipt {a['seq']} at {a['ts']}: `{a['rule']}` allowed; check `{what}` "
                         f"(scope `{pc.get('scope')}`, signed {pc.get('created')}, expires {pc.get('expires')})")
        lines.append("")
    if v.get("tools"):
        lines += ["## Tools used", ""] + [f"- {k}: {n}" for k, n in sorted(v["tools"].items(), key=lambda kv: -kv[1])] + [""]
    if v.get("warnings"):
        lines += ["## Notes", ""] + [f"- {w}" for w in v["warnings"]] + [""]
    lines += ["## What this does not show", ""] + [f"- {x}" for x in v["limits"]] + [""]
    lines += ["Re-check independently: see VERIFY.md.", ""]
    return "\n".join(lines)


def _report_html(v: dict) -> str:
    e = html.escape
    ok = v["valid"]
    rows = [
        ("Recorded", f"{v.get('first_ts')} to {v.get('last_ts')} (local clock)"),
        ("Tool calls", f"{v.get('tool_calls')}"),
        ("Blocked by guard", f"{v.get('blocked')}"),
        ("Sealed", f"through receipt {v.get('sealed_through')} by {v.get('signed_checkpoints')} signed checkpoint(s)"),
        ("Independent timestamps", f"{v.get('anchors')} token(s), through receipt {v.get('anchored_through')} "
                                   f"at {v.get('anchored_time') or 'n/a'}"),
        ("Signer key", ", ".join(v.get("signers") or []) or "none"),
        ("Model (self-reported)", ", ".join(v.get("models") or []) or "unknown"),
    ]
    events = []
    for b in v.get("blocked_calls", []):
        events.append(f"<li class='deny'><b>Blocked</b> receipt {b['seq']} · {e(str(b['ts']))} · {e(str(b['tool']))} "
                      f"· rule <code>{e(str(b['rule']))}</code></li>")
    for a in v.get("allowed_under_precondition", []):
        pc = a["precondition"]
        what = pc.get("check") or pc.get("manual_reason") or "precondition missing from pack"
        events.append(f"<li class='allow'><b>Allowed under safety check</b> receipt {a['seq']} · {e(str(a['ts']))} · "
                      f"rule <code>{e(str(a['rule']))}</code><br>check: <code>{e(str(what))}</code> · scope "
                      f"<code>{e(str(pc.get('scope')))}</code> · signed {e(str(pc.get('created')))}</li>")
    errs = "".join(f"<li>{e(x)}</li>" for x in v.get("errors", []))
    notes = "".join(f"<li>{e(x)}</li>" for x in v.get("warnings", []))
    limits = "".join(f"<li>{e(x)}</li>" for x in v["limits"])
    table = "".join(f"<tr><th>{e(k)}</th><td>{e(val)}</td></tr>" for k, val in rows)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Agent session evidence</title>
<style>
@page {{ size: A4; margin: 14mm; }}
body {{ font: 10.5pt/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #1b1f24; max-width: 180mm; margin: 0 auto; }}
h1 {{ font-size: 15pt; margin: 0 0 2pt; }} h2 {{ font-size: 11pt; margin: 12pt 0 4pt; }}
.sub {{ color: #57606a; margin-bottom: 8pt; word-break: break-all; }}
.verdict {{ display: inline-block; padding: 3pt 9pt; border-radius: 4pt; font-weight: 700; color: #fff;
  background: {'#1a7f37' if ok else '#cf222e'}; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 8pt; }}
th, td {{ text-align: left; padding: 3pt 6pt; border-bottom: 1px solid #d0d7de; vertical-align: top; word-break: break-all; }}
th {{ width: 34%; color: #57606a; font-weight: 600; }}
ul {{ margin: 4pt 0; padding-left: 16pt; }} li {{ margin: 2pt 0; }}
li.deny b {{ color: #cf222e; }} li.allow b {{ color: #1a7f37; }}
code {{ font: 9pt ui-monospace, Consolas, monospace; background: #f6f8fa; padding: 0 2pt; }}
.foot {{ color: #57606a; font-size: 9pt; margin-top: 10pt; }}
</style></head><body>
<h1>Agent session evidence</h1>
<div class="sub">Session {e(str(v.get('session_id')))} · exported {e(v['exported_at'])} · perathos</div>
<span class="verdict">{'VERIFIED' if ok else 'VERIFICATION FAILED'}</span>
<table>{table}</table>
{f'<h2>Verification failures</h2><ul>{errs}</ul>' if errs else ''}
{f'<h2>Destructive actions</h2><ul>{"".join(events)}</ul>' if events else ''}
{f'<h2>Notes</h2><ul>{notes}</ul>' if notes else ''}
<h2>What this evidence does not show</h2><ul>{limits}</ul>
<div class="foot">Every file in this pack is listed with its SHA-256 in MANIFEST.json, which is signed.
Re-check it yourself: <code>pip install 'perathos[anchor]'</code> then <code>perathos evidence verify &lt;pack&gt;</code>.</div>
</body></html>
"""


def _verify_md(v: dict) -> str:
    keys = ", ".join(v.get("signers") or []) or "<signer key>"
    return f"""# How to verify this evidence pack

You do not need to trust the report: re-check everything from the files.

```bash
pip install 'perathos[anchor]'
perathos evidence verify <this folder or .zip> --verify-key {keys.split(',')[0]}
```

This checks that every file matches the signed MANIFEST.json, re-verifies the
receipt chain and every checkpoint signature, and re-verifies each RFC 3161
timestamp in `anchors.jsonl` against the timestamp authority's root.

Confirm the signer key with the session's owner through a separate channel
before relying on it. Receipt format: https://github.com/perathos-protocol/perathos/blob/main/docs/specs/RECEIPT_V1.md
"""
