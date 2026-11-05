"""Independent RFC 3161 timestamps for flight-recorder checkpoints.

A signed checkpoint proves who sealed a session log; it does not prove *when*
(the local clock can lie) or that a later checkpoint was not cut off. An
RFC 3161 timestamp from an outside Time Stamping Authority (TSA) does the
first: the TSA signs "this exact checkpoint hash existed at time T". Anchors
are kept in a separate file, by default outside the project
(``~/.perathos/anchors/<session_id>.jsonl``), so cutting the end off a log
also requires finding and editing the anchors. Keeping a copy of the anchors
somewhere the agent cannot reach (another machine, an auditor, a ticket)
makes that cut detectable.

Trust model: a token is accepted only if it chains to a *pinned* TSA root
shipped with perathos (or supplied by the caller). Certificates embedded in a
token are used only to identify the TSA's signing certificate, never as
trust anchors: passing them as intermediates would let a token carrying its
own self-signed root verify.

The message imprint is SHA-256 over the 32 raw bytes of the checkpoint's
``receipt_hash``.

Needs the optional ``rfc3161-client`` package: ``pip install perathos[anchor]``.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Any

ANCHOR_VERSION = "perathos.anchor/v1"
DEFAULT_TSA_URL = "https://freetsa.org/tsr"
_DEFAULT_ROOTS = ("freetsa_root.pem",)
# A checkpoint stamped more than this long *before* its own local timestamp
# means the local clock was ahead (or the log was back-dated).
_CLOCK_SKEW = timedelta(minutes=5)


class AnchorUnavailable(RuntimeError):
    """The optional rfc3161-client dependency is not installed."""


def _rfc3161():
    try:
        import rfc3161_client
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise AnchorUnavailable(
            "Timestamps need the optional dependency: pip install 'perathos[anchor]'"
        ) from exc
    return rfc3161_client


def default_anchors_path(session_id: str) -> Path:
    return Path.home() / ".perathos" / "anchors" / f"{session_id}.jsonl"


def load_roots(extra_pem_paths: list[str] | None = None):
    """Pinned TSA roots: the ones shipped with perathos plus any supplied."""
    from cryptography import x509

    roots = []
    pkg = resources.files("perathos.data.tsa")
    for name in _DEFAULT_ROOTS:
        roots.extend(x509.load_pem_x509_certificates(pkg.joinpath(name).read_bytes()))
    for p in extra_pem_paths or []:
        roots.extend(x509.load_pem_x509_certificates(Path(p).read_bytes()))
    return roots


def request_timestamp(receipt_hash_hex: str, *, url: str = DEFAULT_TSA_URL, timeout: float = 10.0) -> bytes:
    """Ask a TSA to timestamp a checkpoint hash. Returns the DER response."""
    r = _rfc3161()
    req = (
        r.TimestampRequestBuilder()
        .data(bytes.fromhex(receipt_hash_hex))
        .hash_algorithm(r.HashAlgorithm.SHA256)
        .cert_request(cert_request=True)
        .nonce(nonce=True)
        .build()
    )
    http_req = urllib.request.Request(
        url, data=req.as_bytes(), headers={"Content-Type": "application/timestamp-query"}
    )
    with urllib.request.urlopen(http_req, timeout=timeout) as resp:  # noqa: S310 - TSA URL is operator-chosen
        body = resp.read()
    parsed = r.decode_timestamp_response(body)
    if parsed.status not in (0, 1):  # granted / grantedWithMods
        raise RuntimeError(f"TSA refused the request (status {parsed.status})")
    return body


def verify_timestamp(token_der: bytes, receipt_hash_hex: str, roots) -> tuple[bool, str]:
    """Verify a TSA response over a checkpoint hash against pinned roots.

    Returns (True, gen_time_iso) or (False, error_code).
    """
    from cryptography import x509

    r = _rfc3161()
    try:
        resp = r.decode_timestamp_response(token_der)
    except ValueError:
        return False, "ERR_ANCHOR_MALFORMED"
    certs = [x509.load_der_x509_certificate(c) for c in resp.signed_data.certificates]
    leaves = [c for c in certs if c.subject != c.issuer] or certs
    last_err = "ERR_ANCHOR_UNTRUSTED"
    for leaf in leaves:
        try:
            verifier = r.VerifierBuilder(roots=list(roots)).tsa_certificate(leaf).build()
            verifier.verify_message(resp, bytes.fromhex(receipt_hash_hex))
        except r.VerificationError as exc:
            last_err = "ERR_ANCHOR_MISMATCH" if "Mismatch between messages" in str(exc) else "ERR_ANCHOR_UNTRUSTED"
            continue
        except ValueError:
            continue
        gen = resp.tst_info.gen_time
        if gen.tzinfo is None:
            gen = gen.replace(tzinfo=timezone.utc)
        return True, gen.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return False, last_err


def append_anchor(anchors_path: Path, checkpoint: dict[str, Any], token_der: bytes, url: str, gen_time: str) -> dict:
    anchors_path.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "v": ANCHOR_VERSION,
        "session_id": checkpoint.get("session_id"),
        "seq": checkpoint.get("seq"),
        "receipt_hash": checkpoint.get("receipt_hash"),
        "tsa": url,
        "gen_time": gen_time,
        "token": base64.b64encode(token_der).decode("ascii"),
    }
    line = json.dumps(rec, sort_keys=True) + "\n"
    with open(anchors_path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())
    mirror = anchor_mirror_dir()
    if mirror is not None:
        # A second copy somewhere the agent cannot reach (a network share, a
        # synced folder) is what makes a cut-off log provable later.
        try:
            mirror.mkdir(parents=True, exist_ok=True)
            with open(mirror / anchors_path.name, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass
    return rec


def anchor_mirror_dir() -> Path | None:
    """$PERATHOS_ANCHOR_MIRROR, else `perathos config` anchor_mirror, else None."""
    from .approvers import get_config
    value = os.environ.get("PERATHOS_ANCHOR_MIRROR") or get_config().get("anchor_mirror")
    return Path(value) if value else None


def read_anchors(anchors_path: Path) -> list[dict]:
    out = []
    for line in Path(anchors_path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"_malformed": True})
    return out


def anchor_checkpoint(checkpoint: dict[str, Any], anchors_path: Path, *, url: str = DEFAULT_TSA_URL,
                      roots=None, timeout: float = 10.0) -> dict:
    """Timestamp one checkpoint, verify the token, and append it to the anchors file."""
    token = request_timestamp(checkpoint["receipt_hash"], url=url, timeout=timeout)
    ok, gen_or_err = verify_timestamp(token, checkpoint["receipt_hash"], roots if roots is not None else load_roots())
    if not ok:
        raise RuntimeError(f"TSA response did not verify against pinned roots: {gen_or_err}")
    return append_anchor(anchors_path, checkpoint, token, url, gen_or_err)


def anchor_session(log_path: Path, anchors_path: Path | None = None, *, url: str = DEFAULT_TSA_URL,
                   roots=None, timeout: float = 10.0) -> list[dict]:
    """Anchor every checkpoint in a log that has no anchor yet. Returns new anchors."""
    from .recorder import safe_session_id

    checkpoints = []
    session_id = None
    for line in Path(log_path).read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("kind") == "checkpoint":
            checkpoints.append(rec)
            session_id = rec.get("session_id")
    if not checkpoints:
        return []
    anchors_path = anchors_path or default_anchors_path(safe_session_id(session_id))
    done = {a.get("receipt_hash") for a in read_anchors(anchors_path)} if anchors_path.exists() else set()
    roots = roots if roots is not None else load_roots()
    return [anchor_checkpoint(cp, anchors_path, url=url, roots=roots, timeout=timeout)
            for cp in checkpoints if cp.get("receipt_hash") not in done]


@dataclass
class AnchorReport:
    anchors: int = 0
    verified: int = 0
    anchored_through: int = 0
    anchored_time: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def check_anchors(anchors_path: Path, checkpoint_index: dict[int, dict], sealed_through: int, roots) -> AnchorReport:
    """Cross-check an anchors file against a session log's checkpoints.

    ``checkpoint_index`` maps seq -> checkpoint receipt from the log.
    """
    rep = AnchorReport()
    for a in read_anchors(anchors_path):
        rep.anchors += 1
        if a.get("_malformed") or a.get("v") != ANCHOR_VERSION:
            rep.errors.append("ERR_ANCHOR_MALFORMED: unreadable anchor record")
            continue
        seq, h = a.get("seq"), a.get("receipt_hash")
        cp = checkpoint_index.get(seq) if isinstance(seq, int) else None
        if cp is None or cp.get("receipt_hash") != h:
            if isinstance(seq, int) and seq > sealed_through:
                rep.errors.append(
                    f"ERR_TRUNCATED: an independent timestamp proves checkpoint seq {seq} existed at "
                    f"{a.get('gen_time')}, but the log is sealed only through seq {sealed_through}"
                )
            else:
                rep.errors.append(f"ERR_ANCHOR_MISMATCH: anchor for seq {seq} does not match the log's checkpoint")
            continue
        try:
            token = base64.b64decode(a.get("token", ""), validate=True)
        except ValueError:
            rep.errors.append(f"ERR_ANCHOR_MALFORMED at seq {seq}")
            continue
        ok, gen_or_err = verify_timestamp(token, h, roots)
        if not ok:
            rep.errors.append(f"{gen_or_err} at seq {seq}")
            continue
        rep.verified += 1
        try:
            local = datetime.fromisoformat(str(cp.get("ts")).replace("Z", "+00:00"))
            tsa = datetime.fromisoformat(gen_or_err.replace("Z", "+00:00"))
            if tsa + _CLOCK_SKEW < local:
                rep.warnings.append(
                    f"checkpoint seq {seq} claims local time {cp.get('ts')} but was timestamped earlier, "
                    f"at {gen_or_err}: the local clock was ahead"
                )
        except ValueError:
            pass
        if seq >= rep.anchored_through:
            rep.anchored_through, rep.anchored_time = seq, gen_or_err
    return rep
