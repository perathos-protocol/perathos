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
It also verifies each Gate receipt in ``approvals/`` and checks that every
approval the log cites is in the pack, approved, and for the same arguments,
and that every Gate denial the log cites (``guard.gate.receipt``) is in the
pack, a deny decision, and for the same arguments. Whether the Gate key and
the approver passkeys were ones the verifier already held is reported, not
assumed.

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


def _check_citations(receipts: list[dict], preconditions: set[str], approvals: dict[str, dict | None],
                     pin_issues: dict[str, str] | None = None) -> tuple[list[str], list[str], dict[str, Any]]:
    """Cross-check what the log cites against what the pack holds. Returns (errors, warnings, counts).

    An allowed call that names a precondition must find it in ``preconditions``
    (declared hashes), or nothing shows which safety check it relied on. A call
    the log records as approved must point at an approve decision in
    ``approvals`` (receipt_hash -> receipt, or None for a file that failed its
    own check, which the caller has already reported) for exactly its
    ``args_hash``. Export and ``evidence verify`` both use this, so the
    exporter's report cannot say VALID for a pack whose citations the verifier
    rejects. (They can still differ on pins: export turns a Gate receipt that
    does not match the exporting machine's pins into a warning, which
    ``evidence verify`` reports as an error for an approval; see
    ``export_evidence_pack``.) ``pin_issues`` (receipt_hash -> error code)
    marks Gate receipts that did not match the pins: they are not counted as
    verified.
    """
    errors: list[str] = []
    warnings: list[str] = []
    pc_cited = 0
    cited: dict[str, list] = {}
    verified = 0
    for r in receipts:
        g_field = r.get("guard")
        if r.get("kind") != "pre" or not isinstance(g_field, dict):
            continue
        seq = r.get("seq")
        if g_field.get("decision") != "deny" and g_field.get("precondition"):
            pc_cited += 1
            h = str(g_field["precondition"])
            if h not in preconditions:
                errors.append(f"ERR_PRECONDITION_MISSING: receipt {seq} cites precondition "
                              f"{h[:16]}..., which is not in the pack")
        if not g_field.get("approval"):
            continue
        h = str(g_field["approval"])
        cited.setdefault(h, []).append(seq)
        if h not in approvals:
            errors.append(f"ERR_APPROVAL_MISSING: receipt {seq} cites approval {h[:16]}..., "
                          f"which is not in the pack")
            continue
        g = approvals[h]
        if g is None:
            continue
        request = g.get("request") if isinstance(g.get("request"), dict) else {}
        if g.get("decision") != "approve":
            errors.append(f"ERR_APPROVAL_NOT_APPROVED: receipt {seq} cites approval {h[:16]}..., "
                          f"whose decision is {str(g.get('decision'))[:16]!r}")
        elif request.get("args_hash") != r.get("args_hash"):
            errors.append(f"ERR_APPROVAL_ARGS_MISMATCH: receipt {seq} cites approval {h[:16]}..., "
                          f"which was given for different arguments")
        else:
            verified += 1
    for h, seqs in cited.items():
        if len(seqs) > 1:
            warnings.append(f"approval {h[:16]}... is cited by {len(seqs)} calls (receipts "
                            f"{', '.join(map(str, seqs))}); an approval is meant to be used once")
    counts = {"preconditions_cited": pc_cited, "approvals_cited": sum(len(s) for s in cited.values()),
              "approvals_verified": verified}
    g_errors, g_warnings, g_counts = _check_gate_citations(receipts, approvals, pin_issues)
    errors.extend(g_errors)
    warnings.extend(g_warnings)
    counts.update(g_counts)
    return errors, warnings, counts


GATE_OUTCOMES = ("denied", "timeout", "expired", "unreachable", "rejected")


def _gate_field(r: dict) -> dict | None:
    """A ``pre`` receipt's ``guard.gate`` object (the guard asked Perathos Gate and the call did not run)."""
    g = r.get("guard")
    if r.get("kind") != "pre" or not isinstance(g, dict) or not isinstance(g.get("gate"), dict):
        return None
    return g["gate"]


def _gate_receipt_hashes(receipts: list[dict]) -> tuple[set[str], set[str]]:
    """(every Gate receipt hash the log cites, those cited only by ``guard.gate``, never as an approval)."""
    approvals: set[str] = set()
    gate_cited: set[str] = set()
    for r in receipts:
        g = r.get("guard")
        if r.get("kind") != "pre" or not isinstance(g, dict):
            continue
        if g.get("approval"):
            approvals.add(str(g["approval"]))
        gf = _gate_field(r)
        if gf and gf.get("receipt"):
            gate_cited.add(str(gf["receipt"]))
    return approvals | gate_cited, gate_cited - approvals


# Failures that come only from what the verifier pinned, not from the receipt itself.
_PIN_ONLY = {
    "ERR_GATE_UNTRUSTED_APPROVER": "approver not one you pinned",
    "ERR_GATE_UNEXPECTED_SERVER": "signed by a Gate key other than the pinned one",
}


def _check_gate_citations(receipts: list[dict], in_pack: dict[str, dict | None],
                          pin_issues: dict[str, str] | None = None) -> tuple[list[str], list[str], dict[str, Any]]:
    """Cross-check each ``guard.gate`` field against the Gate receipts in the pack.

    A cited receipt must be in the pack (``ERR_GATE_RECEIPT_MISSING``) and be
    for exactly the call's ``args_hash`` (``ERR_GATE_RECEIPT_ARGS_MISMATCH``);
    for a ``denied`` outcome it must be a deny decision
    (``ERR_GATE_RECEIPT_NOT_DENIED``). A ``denied`` outcome with no receipt is a
    warning: nothing signed backs it.
    """
    errors: list[str] = []
    warnings: list[str] = []
    outcomes: dict[str, int] = {}
    cited = present = verified = 0
    for r in receipts:
        gf = _gate_field(r)
        if gf is None:
            continue
        seq = r.get("seq")
        outcome = str(gf.get("outcome"))
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        if outcome not in GATE_OUTCOMES:
            warnings.append(f"receipt {seq}: unknown Gate outcome {outcome[:24]!r}")
        if r.get("guard", {}).get("decision") != "deny":
            warnings.append(f"receipt {seq}: names a Gate outcome but the guard's decision is not deny")
        if not gf.get("receipt"):
            if outcome == "denied":
                warnings.append(f"receipt {seq}: Gate denial not backed by a signed receipt")
            continue
        h = str(gf["receipt"])
        cited += 1
        if h not in in_pack:
            errors.append(f"ERR_GATE_RECEIPT_MISSING: receipt {seq} cites Gate receipt {h[:16]}..., "
                          f"which is not in the pack")
            continue
        present += 1
        g = in_pack[h]
        if g is None:
            continue  # failed its own check; reported where the file was checked
        request = g.get("request") if isinstance(g.get("request"), dict) else {}
        problem = None
        if outcome == "denied" and g.get("decision") != "deny":
            problem = (f"ERR_GATE_RECEIPT_NOT_DENIED: receipt {seq} records a denial and cites Gate receipt "
                       f"{h[:16]}..., whose decision is {str(g.get('decision'))[:16]!r}")
        elif request.get("args_hash") != r.get("args_hash"):
            problem = (f"ERR_GATE_RECEIPT_ARGS_MISMATCH: receipt {seq} cites Gate receipt {h[:16]}..., "
                       f"which was given for different arguments")
        if problem is not None:
            errors.append(problem)
        elif h not in (pin_issues or {}):  # a pin mismatch is counted in pin_mismatches, not here
            verified += 1
    return errors, warnings, {"gate_receipts_cited": cited, "gate_receipts_in_pack": present,
                              "gate_receipts_verified": verified, "gate_outcomes": outcomes}


def _check_gate_files(files: list[Path], receipts: list[dict], gate_key, pins, *, pins_warn_all: bool = False):
    """Verify each Gate receipt file (server and approver passkey signatures, against the
    Gate key and approver passkeys given, if any).

    Returns (errors, warnings, in_pack, pin_issues, gate_only, gate_keys_seen, approvers_seen).
    ``in_pack`` maps each declared receipt_hash to its receipt, or to None when the
    file failed its own check. Integrity failures (hash, signatures, malformed) are
    always errors. A failure that comes only from the pins (approver not pinned, a
    Gate key other than the pinned one) is a warning, recorded in ``pin_issues``,
    for a receipt the log cites only through ``guard.gate`` (a denial authorises
    nothing), and for every receipt when ``pins_warn_all`` (export: the exporting
    machine's pins may have changed since). ``gate_only`` is the set of receipt
    hashes cited only through ``guard.gate``.
    """
    from .gate import verify_receipt as _verify_gate

    _, gate_only = _gate_receipt_hashes(receipts)
    errors: list[str] = []
    warnings: list[str] = []
    in_pack: dict[str, dict | None] = {}
    pin_issues: dict[str, str] = {}
    gate_keys_seen: list[str] = []
    approvers_seen: list[dict] = []
    for f in files:
        try:
            g = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            g = None
        if not isinstance(g, dict):
            errors.append(f"ERR_APPROVAL_MALFORMED: {f.name}")
            continue
        h = str(g.get("receipt_hash"))
        chk = _verify_gate(g, gate_key=gate_key, trusted_approvers=pins)
        if not chk:
            code = chk.error.split(":")[0]
            # Pin-only when the same receipt verifies with no pins at all.
            pin_only = code in _PIN_ONLY and bool(_verify_gate(g, gate_key=None, trusted_approvers=None))
            if not (pin_only and (pins_warn_all or h in gate_only)):
                errors.append(f"{code}: {f.name}")
                in_pack.setdefault(h, None)
                continue
            pin_issues[h] = code
            warnings.append(f"{f.name}: {_PIN_ONLY[code]} ({code}); its signatures are valid"
                            + ("; a denial authorises nothing" if h in gate_only else ""))
        in_pack[h] = g
        vk = g["server_signature"].get("verify_key")
        if vk not in gate_keys_seen:
            gate_keys_seen.append(vk)
        who = {"name": g["approver"].get("name"), "public_key": g["approver"].get("public_key")}
        if who not in approvers_seen:
            approvers_seen.append(who)
    return errors, warnings, in_pack, pin_issues, gate_only, gate_keys_seen, approvers_seen


def _summarise(receipts: list[dict], preconditions: dict[str, dict],
               gate_receipts: dict[str, dict | None] | None = None,
               pin_issues: dict[str, str] | None = None) -> dict[str, Any]:
    """What the guard did, call by call, for the report.

    ``gate_receipts`` maps receipt_hash to a Gate receipt in the pack (None when
    it failed verification); ``pin_issues`` maps a receipt_hash to the pin-only
    error it had. An allow under a person's approval is listed in
    ``approved_by_person``, not as a precondition allow.
    """
    gate_receipts = gate_receipts or {}
    pin_issues = pin_issues or {}

    def receipt_info(h) -> dict:
        h = str(h) if h else None
        g = gate_receipts.get(h) if h else None
        approver = g.get("approver") if isinstance(g, dict) and isinstance(g.get("approver"), dict) else {}
        issue = pin_issues.get(h) if h else None
        return {"receipt": h, "receipt_in_pack": bool(h) and h in gate_receipts,
                "receipt_verified": isinstance(g, dict) and issue is None,
                "pin_issue": _PIN_ONLY.get(issue) if issue else None, "approver": approver.get("name"),
                "decided_at": g.get("decided_at") if isinstance(g, dict) else None}

    blocked, allowed, approved = [], [], []
    for r in receipts:
        g = r.get("guard")
        if r.get("kind") == "pre" and isinstance(g, dict):
            item = {"seq": r.get("seq"), "ts": r.get("ts"), "tool": r.get("tool"), "rule": g.get("rule")}
            if g.get("decision") == "deny":
                gf = _gate_field(r)
                item["gate"] = ({"approval_id": gf.get("approval_id"), "outcome": gf.get("outcome"),
                                 **receipt_info(gf.get("receipt"))} if gf is not None else None)
                blocked.append(item)
            elif g.get("approval"):
                approved.append({**item, **receipt_info(g["approval"])})
            else:
                pc = preconditions.get(str(g.get("precondition")))
                item["precondition"] = {
                    "id": pc.get("id"), "scope": pc.get("scope"), "check": pc.get("check"),
                    "manual_reason": pc.get("manual_reason"), "created": pc.get("created"),
                    "expires": pc.get("expires"),
                } if pc else {"hash": g.get("precondition"), "missing": True}
                allowed.append(item)
    return {"blocked_calls": blocked, "allowed_under_precondition": allowed, "approved_by_person": approved}


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

    from .approvers import list_approvers
    approvers = list_approvers()
    if approvers:
        # Public keys and names only, so a reviewer can see who approved what.
        (out / "approvers.json").write_text(json.dumps({"approvers": approvers}, indent=2), encoding="utf-8")

    receipts = _read_receipts(log)
    # Gate receipts the log cites: approvals that allowed a call, and denials (guard.gate.receipt).
    approval_hashes, _ = _gate_receipt_hashes(receipts)
    approvals: dict[str, dict] = {}
    ap_dir = _project_root_for(log) / ".perathos" / "approvals"
    if approval_hashes and ap_dir.exists():
        (out / "approvals").mkdir()
        for f in ap_dir.glob("apr_*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(rec, dict) and rec.get("receipt_hash") in approval_hashes:
                shutil.copyfile(f, out / "approvals" / f.name)
                approvals[rec["receipt_hash"]] = rec
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
    # Gate receipts are checked against the Gate key and approver passkeys pinned on the
    # exporting machine, if any, and the report says which. Those pins may have changed
    # since the receipt was made (a rotated Gate key, an approver pinned later), so here a
    # pin-only mismatch is a warning; integrity failures fail the export. A reviewer
    # re-checks with keys of their own: `evidence verify --gate-key ... --approver-key ...`.
    gate_check = {"gate_key_pinned": False, "gate_key_confirmed": False, "gate_key_source": None,
                  "approvers_pinned": False, "approvers_source": None}
    gate_receipts: dict[str, dict | None] = {}
    pin_issues: dict[str, str] = {}
    if approvals:
        gate_key, key_src, pins, pins_src = _gate_pins(None, None, True)
        gate_check = {"gate_key_pinned": gate_key is not None, "gate_key_confirmed": gate_key is not None,
                      "gate_key_source": key_src, "approvers_pinned": pins is not None, "approvers_source": pins_src}
        g_errors, g_warnings, gate_receipts, pin_issues, _, _, _ = _check_gate_files(
            sorted((out / "approvals").glob("*.json")), receipts, gate_key, pins, pins_warn_all=True)
        for e in g_errors:
            report.fail(e)
        report.warnings.extend(g_warnings)
    # The same cross-check `evidence verify` makes.
    cite_errors, cite_warnings, _ = _check_citations(receipts, set(preconditions), dict(gate_receipts))
    for e in cite_errors:
        report.fail(e)
    report.warnings.extend(cite_warnings)
    summary = _summarise(receipts, preconditions, gate_receipts, pin_issues)
    # A pin mismatch never fails the export (the pins may have changed since), but it must not
    # read as a match: gate_key_confirmed is true only when every cited Gate receipt was signed
    # by the pinned key, and an approval that allowed a call against the pins is flagged.
    pin_calls = ([("approval", a) for a in summary["approved_by_person"] if a.get("pin_issue")]
                 + [("denial", b["gate"]) for b in summary["blocked_calls"] if b.get("gate") and b["gate"].get("pin_issue")])
    gate_check["pin_mismatches"] = {"approvals": sum(1 for k, _ in pin_calls if k == "approval"),
                                    "denials": sum(1 for k, _ in pin_calls if k == "denial")}
    if any(code == "ERR_GATE_UNEXPECTED_SERVER" for code in pin_issues.values()):
        gate_check["gate_key_confirmed"] = False
    missing = [a["precondition"]["hash"] for a in summary["allowed_under_precondition"]
               if a["precondition"].get("missing")]
    verification = {**report.to_dict(), "path": "session.jsonl", **summary, "gate_check": gate_check,
                    "warnings_require_attention": gate_check["pin_mismatches"]["approvals"] > 0,
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
        from .keytrust import coerce_signer
        from .signing import sign_hash_with_signer
        manifest["signature"] = sign_hash_with_signer(manifest["manifest_hash"], coerce_signer(signing_key_hex))
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    zip_path = None
    if make_zip:
        zip_path = out.with_suffix(".zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(out.rglob("*")):
                if f.is_file():
                    z.write(f, f"{out.name}/{f.relative_to(out).as_posix()}")
    return {"dir": out, "zip": zip_path, "valid": report.valid, "report": verification}


def _gate_pins(gate_key, approver_keys, use_local_pins: bool):
    """(gate key, where from, approver passkey pins, where from) for checking approvals.

    Explicit values win. Otherwise, with ``use_local_pins``, the Gate key and
    approver passkeys pinned in this machine's config are used (the same
    sources as ``perathos gate verify``). A reviewer's machine usually has
    neither, so both can come back None: the caller must report that.
    """
    gate_key = str(gate_key).strip().lower() if gate_key else None
    key_src = "argument" if gate_key else None
    pins = frozenset(str(k).strip() for k in approver_keys if str(k).strip()) if approver_keys else None
    pins_src = "argument" if pins else None
    if use_local_pins:
        from .approvers import get_config
        from .gate import trusted_approver_keys
        if gate_key is None:
            gate_key = get_config().get("gate_key") or None
            key_src = "local pin" if gate_key else None
        if not pins:
            pins = trusted_approver_keys()
            pins_src = "local pin" if pins else None
    return gate_key, key_src, pins or None, pins_src


def verify_evidence_pack(pack: str | Path, *, expected_verify_key: str | None = None, tsa_roots=None,
                         gate_key: str | None = None, approver_keys=None,
                         use_local_pins: bool = True) -> dict[str, Any]:
    """Re-check a pack from its own files. Accepts a directory or a .zip.

    Gate approval receipts are verified against ``gate_key`` (the Gate server's
    Ed25519 public key, hex) and ``approver_keys`` (approver passkey public
    keys, base64url, as shown by ``perathos gate approvers``). When either is
    not given, the one pinned in this machine's config is used if there is one
    (``use_local_pins=False`` turns that off). The result's ``approvals`` block
    says whether the Gate key was confirmed and whether approvers were pinned:
    without them a receipt shows only that *some* key pair signed it.

    Every approval a ``pre`` receipt cites must be in the pack, be an approve
    decision, and be for the same ``args_hash`` as the call that cites it.
    Every Gate receipt a ``guard.gate`` field cites must be in the pack
    (``ERR_GATE_RECEIPT_MISSING``), verify like an approval, and, for a
    ``denied`` outcome, be a deny decision (``ERR_GATE_RECEIPT_NOT_DENIED``)
    for the same ``args_hash`` (``ERR_GATE_RECEIPT_ARGS_MISMATCH``).
    Every precondition an allowed call cites must be in the pack
    (``ERR_PRECONDITION_MISSING``), and the head witness must match the log's
    checkpoint at its seq (``ERR_TRUNCATED`` / ``ERR_HEAD_MISMATCH``).
    """
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
        # Preconditions carried in the pack must be intact and signed (their
        # expiry is history by now, so it is not re-checked).
        from .guard import precondition_hash
        pc_files = sorted((pack / "preconditions").glob("*.json")) if (pack / "preconditions").exists() else []
        pc_in_pack: set[str] = set()  # declared precondition_hash of every readable file
        for f in pc_files:
            try:
                pc = json.loads(f.read_text(encoding="utf-8"))
                pc_in_pack.add(str(pc.get("precondition_hash")))
                if precondition_hash(pc) != pc.get("precondition_hash"):
                    errors.append(f"ERR_PRECONDITION_MODIFIED: {f.name}")
                    continue
                ok, err = verify_signature(str(pc.get("precondition_hash")), pc.get("signature") or {})
                if not ok or (pc.get("signature") or {}).get("verify_key") != pc.get("signer"):
                    errors.append(f"ERR_PRECONDITION_SIGNATURE: {f.name}")
            except (OSError, ValueError, TypeError, AttributeError):
                errors.append(f"ERR_PRECONDITION_MALFORMED: {f.name}")
        # Gate receipts (approvals and denials): each must verify (server and approver passkey
        # signatures), against the Gate key and the approver passkeys the verifier holds, if any.
        gate_key, gate_key_src, pins, pins_src = _gate_pins(gate_key, approver_keys, use_local_pins)
        receipts = _read_receipts(pack / "session.jsonl") if (pack / "session.jsonl").exists() else []
        ap_files = sorted((pack / "approvals").glob("*.json")) if (pack / "approvals").exists() else []
        g_errors, warnings, in_pack, pin_issues, gate_only, gate_keys_seen, approvers_seen = _check_gate_files(
            ap_files, receipts, gate_key, pins)
        errors.extend(g_errors)
        # approvals/ also holds denial receipts; count only the approvals here.
        ap_in_pack = 0
        for f in ap_files:
            try:
                declared = str(json.loads(f.read_text(encoding="utf-8")).get("receipt_hash"))
            except (OSError, ValueError, AttributeError):
                declared = None
            if declared not in gate_only:
                ap_in_pack += 1
        # Cross-check the log against the preconditions and Gate receipts in the pack. (A file
        # that failed its own check above still counts as present; its failure is reported.)
        cite_errors, cite_warnings, counts = _check_citations(receipts, pc_in_pack, in_pack, pin_issues)
        errors.extend(cite_errors)
        warnings.extend(cite_warnings)
        approvals_report = {
            "cited": counts["approvals_cited"], "in_pack": ap_in_pack, "verified": counts["approvals_verified"],
            "gate_key_confirmed": gate_key is not None, "gate_key_source": gate_key_src,
            "approvers_pinned": pins is not None, "approvers_source": pins_src,
            "gate_keys": gate_keys_seen, "approvers": approvers_seen,
        }
        anchors = pack / "anchors.jsonl"
        # session.head.json sits beside session.jsonl in the pack, so session verify finds it and
        # applies the same head check as on a live log: ERR_TRUNCATED or ERR_HEAD_MISMATCH.
        rep = verify_session(pack / "session.jsonl", expected_verify_key=expected_verify_key,
                             anchors_path=anchors if anchors.exists() else None, tsa_roots=tsa_roots,
                             check_head=True)
        errors.extend(rep.errors)
        gate_receipts_report = {
            "cited": counts["gate_receipts_cited"], "in_pack": counts["gate_receipts_in_pack"],
            "verified": counts["gate_receipts_verified"], "outcomes": counts["gate_outcomes"],
            "pin_mismatches": sum(1 for h in pin_issues if h in gate_only),
        }
        return {"valid": not errors, "errors": errors, "warnings": warnings, "session": rep.to_dict(),
                "approvals": approvals_report, "gate_receipts": gate_receipts_report,
                "preconditions": {"cited": counts["preconditions_cited"], "in_pack": len(pc_files)}}
    finally:
        if tmp is not None:
            tmp.cleanup()


# --------------------------------------------------------------------------- #
# Human-readable report
# --------------------------------------------------------------------------- #

def _gate_receipt_status(item: dict, gc: dict) -> str:
    """How far a Gate receipt cited in the report was checked at export."""
    if not item.get("receipt_in_pack"):
        return "receipt MISSING from the pack"
    if item.get("pin_issue"):
        return f"receipt signatures valid at export, but {item['pin_issue']}"
    if not item.get("receipt_verified"):
        return "receipt FAILED verification"
    # A receipt with no pin issue matched the pinned key, if one was pinned.
    key = (f"Gate key confirmed ({gc.get('gate_key_source')})" if gc.get("gate_key_pinned", gc.get("gate_key_confirmed"))
           else "Gate key UNCONFIRMED")
    who = (f"approver pinned ({gc.get('approvers_source')})" if gc.get("approvers_pinned")
           else "approver NOT PINNED")
    return f"receipt verified at export, {key}, {who}"


def _short(h) -> str:
    return f"{str(h)[:16]}..."


def _approved_text(a: dict, gc: dict) -> str:
    """'approved by <name> with a passkey at <time> (Gate receipt <hash>; <status>)'."""
    who = a.get("approver") or "an approver not named in the pack"
    at = f" at {a['decided_at']}" if a.get("decided_at") else ""
    return f"approved by {who} with a passkey{at} (Gate receipt {_short(a.get('receipt'))}; {_gate_receipt_status(a, gc)})"


def _blocked_text(b: dict, gc: dict) -> str:
    """What stopped a call: the rule alone, or what came of asking a person through Perathos Gate."""
    gf = b.get("gate")
    if not gf:
        return f"blocked by rule {b.get('rule')}"
    outcome = gf.get("outcome")
    req = f"Gate request {gf['approval_id']}" if gf.get("approval_id") else "Gate request"
    if outcome == "denied":
        if not gf.get("receipt"):
            return f"the Gate reported a denial; no verified denial receipt recorded ({req})"
        who = gf.get("approver") or "an approver not named in the pack"
        at = f" at {gf['decided_at']}" if gf.get("decided_at") else ""
        return (f"denied by {who} with a passkey{at} (Gate receipt {_short(gf['receipt'])}; "
                f"{_gate_receipt_status(gf, gc)})")
    if outcome == "timeout":
        return f"sent to a person ({req}); no decision before the wait ended"
    if outcome == "expired":
        return f"sent to a person ({req}); request expired"
    if outcome == "unreachable":
        return "Gate unreachable, so no person was asked" if not gf.get("approval_id") else f"Gate unreachable ({req})"
    if outcome == "rejected":
        tail = (f"Gate receipt {_short(gf['receipt'])}; {_gate_receipt_status(gf, gc)}" if gf.get("receipt")
                else "no receipt recorded")
        return f"an approval came back but failed the guard's checks ({req}; {tail})"
    return f"Gate outcome {str(outcome)[:24]!r} ({req})"


def pin_verdict(v: dict) -> str | None:
    """The qualifier a VALID export carries when an approval that allowed a call does not match
    the exporting machine's pins, e.g. 'VALID, BUT 1 Gate approval does not match ...'."""
    n = ((v.get("gate_check") or {}).get("pin_mismatches") or {}).get("approvals", 0)
    if not v.get("valid") or not n:
        return None
    what = "1 Gate approval does" if n == 1 else f"{n} Gate approvals do"
    return (f"VALID, BUT {what} not match this machine's pins "
            f"(check with `perathos evidence verify --gate-key … --approver-key …`)")


def _denial_pin_note(v: dict) -> str | None:
    n = ((v.get("gate_check") or {}).get("pin_mismatches") or {}).get("denials", 0)
    if not n:
        return None
    what = "1 Gate denial receipt does" if n == 1 else f"{n} Gate denial receipts do"
    return f"Note: {what} not match this machine's pins; a denial authorises nothing."


def _report_md(v: dict) -> str:
    status = pin_verdict(v) or ("VALID" if v["valid"] else "INVALID")
    note = _denial_pin_note(v)
    lines = [
        f"# Agent session evidence: {v.get('session_id')}",
        "",
        f"**Verification: {status}**",
        "",
    ] + ([note, ""] if note else []) + [
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
    gc = v.get("gate_check") or {}
    if v.get("blocked_calls"):
        lines += ["## Destructive calls blocked", ""]
        for b in v["blocked_calls"]:
            if b.get("gate"):
                lines.append(f"- receipt {b['seq']} at {b['ts']}: {b['tool']} matched `{b['rule']}`; "
                             f"{_blocked_text(b, gc)}")
            else:
                lines.append(f"- receipt {b['seq']} at {b['ts']}: {b['tool']} blocked by rule `{b['rule']}`")
        lines.append("")
    if v.get("approved_by_person"):
        lines += ["## Destructive calls approved by a person (Perathos Gate)", ""]
        for a in v["approved_by_person"]:
            lines.append(f"- receipt {a['seq']} at {a['ts']}: `{a['rule']}` {_approved_text(a, gc)}")
        lines.append("")
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
    qualified = pin_verdict(v)
    denial_note = _denial_pin_note(v)
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
    gc = v.get("gate_check") or {}
    events = []
    for b in v.get("blocked_calls", []):
        how = f"<br>{e(_blocked_text(b, gc))}" if b.get("gate") else ""
        events.append(f"<li class='deny'><b>Blocked</b> receipt {b['seq']} · {e(str(b['ts']))} · {e(str(b['tool']))} "
                      f"· rule <code>{e(str(b['rule']))}</code>{how}</li>")
    for a in v.get("approved_by_person", []):
        events.append(f"<li class='allow'><b>Approved by a person</b> receipt {a['seq']} · {e(str(a['ts']))} · "
                      f"{e(str(a['tool']))} · rule <code>{e(str(a['rule']))}</code><br>{e(_approved_text(a, gc))}</li>")
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
  background: {'#9a6700' if qualified else '#1a7f37' if ok else '#cf222e'}; }}
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
<span class="verdict">{e(qualified) if qualified else ('VERIFIED' if ok else 'VERIFICATION FAILED')}</span>
{f'<p class="sub">{e(denial_note)}</p>' if denial_note else ''}
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

If the pack has an `approvals/` folder (a person approved or denied an action
through Perathos Gate), also pass `--gate-key <Gate server key>` and
`--approver-key <approver passkey public key>` (repeatable). Without them the
output says `Gate key UNCONFIRMED` or `approvers NOT PINNED`: the approvals are
then internally consistent, but could have been signed by any key pair.

Confirm the signer key (and the Gate and approver keys) with the session's
owner through a separate channel before relying on them. Receipt format: https://github.com/perathos-protocol/perathos/blob/main/docs/specs/RECEIPT_V1.md
"""
