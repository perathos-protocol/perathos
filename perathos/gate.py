"""Perathos Gate: human approval for irreversible agent actions (spec: docs/specs/GATE_V1.md).

This module is shared by both sides:

* the **client** used by the guard (`GateClient`: create a request, wait for the decision);
* the **receipt** format: hashes, the WebAuthn decision challenge, receipt construction
  (used by the Gate server) and offline verification (used by everyone).

A receipt proves that a named person approved or denied *this exact action* on their own
device: the WebAuthn challenge is a hash of the request and the decision, the approver's
passkey signed it with user verification, and the Gate server signed the whole receipt.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import os
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes

REQUEST_VERSION = "perathos.gate.request/v1"
CHALLENGE_VERSION = "perathos.gate.challenge/v1"
RECEIPT_VERSION = "perathos.gate.receipt/v1"
DECISIONS = ("approve", "deny")
_B32 = "abcdefghijklmnopqrstuvwxyz234567"

# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def chash(obj: Any) -> str:
    """Lowercase hex SHA-256 of canonical JSON."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def now_iso(delta_seconds: int = 0) -> str:
    t = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=delta_seconds)
    return t.isoformat().replace("+00:00", "Z")


def parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(str(text).replace("Z", "+00:00"))


def new_request_id() -> str:
    return "apr_" + "".join(secrets.choice(_B32) for _ in range(26))


# --------------------------------------------------------------------------- #
# Request, challenge, receipt
# --------------------------------------------------------------------------- #


def build_request(*, org: str, gate: str, action: dict, agent: dict, args_hash: str,
                  ttl_seconds: int = 600, request_id: str | None = None) -> dict:
    """The request object the server stores (and the approver sees)."""
    if not 60 <= int(ttl_seconds) <= 3600:
        raise ValueError("ttl_seconds must be between 60 and 3600")
    act = {k: str(v)[:4000] for k, v in action.items() if k in ("tool", "summary", "rule", "detail", "target") and v}
    if not act.get("summary"):
        raise ValueError("action.summary is required")
    ag = {k: str(v)[:200] for k, v in (agent or {}).items() if k in ("name", "session_id", "host") and v}
    return {
        "v": REQUEST_VERSION,
        "id": request_id or new_request_id(),
        "org": org,
        "gate": gate,
        "action": act,
        "agent": ag,
        "args_hash": args_hash,
        "created_at": now_iso(),
        "expires_at": now_iso(int(ttl_seconds)),
    }


def decision_challenge(request_hash: str, decision: str) -> bytes:
    """The 32-byte WebAuthn challenge binding a decision to a request."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")
    return hashlib.sha256(canonical_bytes(
        {"v": CHALLENGE_VERSION, "request_hash": request_hash, "decision": decision})).digest()


def receipt_body_hash(receipt: dict) -> str:
    return chash({k: v for k, v in receipt.items() if k not in ("receipt_hash", "server_signature")})


def build_receipt(*, request: dict, decision: str, approver: dict, rp: dict, webauthn: dict,
                  server_signer, valid_seconds: int = 600, decided_at: str | None = None) -> dict:
    """Assemble and server-sign a receipt (used by the Gate server after it has verified the
    WebAuthn assertion). ``server_signer`` is a keytrust.Signer or 64-hex Ed25519 key."""
    from .keytrust import coerce_signer
    from .signing import sign_hash_with_signer

    decided_at = decided_at or now_iso()
    receipt = {
        "v": RECEIPT_VERSION,
        "request": request,
        "request_hash": chash(request),
        "decision": decision,
        "decided_at": decided_at,
        "valid_until": (parse_iso(decided_at) + timedelta(seconds=valid_seconds)).isoformat().replace("+00:00", "Z"),
        "approver": {k: approver[k] for k in ("name", "credential_id", "public_key", "alg", "enrolled_at") if k in approver},
        "rp": {"id": rp["id"], "origin": rp["origin"]},
        "webauthn": {k: webauthn[k] for k in ("authenticator_data", "client_data_json", "signature")},
    }
    receipt["receipt_hash"] = receipt_body_hash(receipt)
    receipt["server_signature"] = sign_hash_with_signer(receipt["receipt_hash"], coerce_signer(server_signer))
    return receipt


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


@dataclass
class ReceiptCheck:
    ok: bool
    error: str = ""

    def __bool__(self) -> bool:
        return self.ok


def _verify_webauthn_sig(public_key_der: bytes, alg: int, signed: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    key = serialization.load_der_public_key(public_key_der)
    try:
        if alg == -7 and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == -8 and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, signed)
        elif alg == -257 and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except InvalidSignature:
        return False
    return True


def trusted_approver_keys() -> frozenset[str] | None:
    """Approver passkey public keys pinned with `perathos gate trust`, or None when none are pinned.

    PERATHOS_GATE_APPROVERS (public keys separated by commas or whitespace) takes precedence,
    for CI runners and other machines with no config file."""
    from .approvers import get_config
    env = os.environ.get("PERATHOS_GATE_APPROVERS", "").replace(",", " ").split()
    if env:
        return frozenset(env)
    pinned = get_config().get("gate_approvers")
    if not isinstance(pinned, list) or not pinned:
        return None
    return frozenset(str(a.get("public_key")) for a in pinned if isinstance(a, dict) and a.get("public_key"))


def verify_receipt(receipt: dict, *, gate_key: str | None, require_user_verification: bool = True,
                   trusted_approvers=None) -> ReceiptCheck:
    """Offline verification of a Gate receipt (spec steps 1-6). Does not check decision,
    expiry or args binding: see ``check_approval_for`` for the guard's use.

    The approver's public key is read from the receipt, so without ``trusted_approvers`` (a set
    of pinned passkey public keys) the receipt shows only that the Gate server vouched for
    this approver: whoever holds the Gate signing key could name a key of their own."""
    from .signing import verify_signature

    try:
        if receipt.get("v") != RECEIPT_VERSION:
            return ReceiptCheck(False, "ERR_GATE_VERSION")
        if receipt_body_hash(receipt) != receipt.get("receipt_hash"):
            return ReceiptCheck(False, "ERR_GATE_RECEIPT_HASH: receipt was modified")
        sig = receipt.get("server_signature")
        ok, err = verify_signature(str(receipt["receipt_hash"]), sig) if isinstance(sig, dict) else (False, "unsigned")
        if not ok:
            return ReceiptCheck(False, f"ERR_GATE_SERVER_SIGNATURE: {err}")
        if gate_key is not None and sig.get("verify_key") != gate_key:
            return ReceiptCheck(False, "ERR_GATE_UNEXPECTED_SERVER: signed by a different Gate key")
        request = receipt["request"]
        if chash(request) != receipt.get("request_hash"):
            return ReceiptCheck(False, "ERR_GATE_REQUEST_HASH")
        decision = receipt.get("decision")
        if decision not in DECISIONS:
            return ReceiptCheck(False, "ERR_GATE_DECISION")

        wa = receipt["webauthn"]
        client_data_raw = b64url_decode(wa["client_data_json"])
        client_data = json.loads(client_data_raw)
        expected_challenge = b64url(decision_challenge(receipt["request_hash"], decision))
        if client_data.get("type") != "webauthn.get":
            return ReceiptCheck(False, "ERR_GATE_WEBAUTHN_TYPE")
        if client_data.get("challenge") != expected_challenge:
            return ReceiptCheck(False, "ERR_GATE_CHALLENGE: the passkey signed a different action or decision")
        rp = receipt["rp"]
        if client_data.get("origin") != rp["origin"]:
            return ReceiptCheck(False, "ERR_GATE_ORIGIN")
        auth_data = b64url_decode(wa["authenticator_data"])
        if len(auth_data) < 37 or auth_data[:32] != hashlib.sha256(rp["id"].encode()).digest():
            return ReceiptCheck(False, "ERR_GATE_RP_ID")
        flags = auth_data[32]
        if not flags & 0x01:
            return ReceiptCheck(False, "ERR_GATE_USER_PRESENCE")
        if require_user_verification and not flags & 0x04:
            return ReceiptCheck(False, "ERR_GATE_USER_VERIFICATION: no biometric or PIN check")
        approver = receipt["approver"]
        signed = auth_data + hashlib.sha256(client_data_raw).digest()
        if not _verify_webauthn_sig(b64url_decode(approver["public_key"]), int(approver["alg"]), signed,
                                    b64url_decode(wa["signature"])):
            return ReceiptCheck(False, "ERR_GATE_APPROVER_SIGNATURE: the approver's passkey signature does not verify")
        if trusted_approvers is not None and approver["public_key"] not in trusted_approvers:
            return ReceiptCheck(False, "ERR_GATE_UNTRUSTED_APPROVER: the approver's passkey is not one you pinned")
    except (KeyError, TypeError, ValueError) as exc:
        return ReceiptCheck(False, f"ERR_GATE_MALFORMED: {type(exc).__name__}: {exc}")
    return ReceiptCheck(True)


def check_approval_for(receipt: dict, *, gate_key: str | None, args_hash: str, now: datetime | None = None,
                       trusted_approvers=None) -> ReceiptCheck:
    """Can this receipt authorise running the action with these arguments right now?"""
    res = verify_receipt(receipt, gate_key=gate_key, trusted_approvers=trusted_approvers)
    if not res:
        return res
    if receipt["decision"] != "approve":
        return ReceiptCheck(False, "ERR_GATE_DENIED: the approver denied this action")
    if receipt["request"].get("args_hash") != args_hash:
        return ReceiptCheck(False, "ERR_GATE_ARGS: approval was for different arguments")
    now = now or datetime.now(timezone.utc)
    if now >= parse_iso(receipt["valid_until"]):
        return ReceiptCheck(False, "ERR_GATE_EXPIRED: approval window has passed")
    return ReceiptCheck(True)


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class GateError(RuntimeError):
    pass


class GateClient:
    """Agent-side client. Configure with `perathos gate login` or env vars
    PERATHOS_GATE_URL / PERATHOS_GATE_API_KEY / PERATHOS_GATE_KEY."""

    def __init__(self, url: str, api_key: str, *, gate_key: str | None = None, timeout: float = 15.0):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.gate_key = gate_key
        self.timeout = timeout

    @classmethod
    def from_config(cls) -> GateClient | None:
        from .approvers import get_config
        cfg = get_config()
        url = os.environ.get("PERATHOS_GATE_URL") or cfg.get("gate_url")
        key = os.environ.get("PERATHOS_GATE_API_KEY") or cfg.get("gate_api_key")
        if not url or not key:
            return None
        return cls(url, key, gate_key=os.environ.get("PERATHOS_GATE_KEY") or cfg.get("gate_key"))

    def _call(self, method: str, path: str, body: dict | None = None, *, timeout: float | None = None, auth: bool = True) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.url + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:  # noqa: S310 - operator-configured URL
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise GateError(f"{method} {path}: HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise GateError(f"{method} {path}: {exc}") from exc

    def info(self) -> dict:
        return self._call("GET", "/.well-known/perathos-gate.json", auth=False)

    def request(self, *, action: dict, agent: dict, args_hash: str, ttl_seconds: int = 600) -> dict:
        return self._call("POST", "/v1/approvals",
                          {"action": action, "agent": agent, "args_hash": args_hash, "ttl_seconds": ttl_seconds})

    def status(self, approval_id: str, wait: int = 0) -> dict:
        wait = max(0, min(int(wait), 60))
        return self._call("GET", f"/v1/approvals/{approval_id}?wait={wait}", timeout=wait + self.timeout)

    def wait_for_decision(self, approval_id: str, total_seconds: int) -> dict:
        """Long-poll until decided, expired, or total_seconds pass. Returns the last status."""
        import time
        deadline = time.monotonic() + max(0, total_seconds)
        st = self.status(approval_id, 0)
        while st.get("status") == "pending" and time.monotonic() < deadline:
            st = self.status(approval_id, int(min(60, max(1, deadline - time.monotonic()))))
        return st


# --------------------------------------------------------------------------- #
# Guard integration: ask a person when the guard blocks an action
# --------------------------------------------------------------------------- #


def approvals_dir(cwd) -> Path:
    return Path(cwd) / ".perathos" / "approvals"


def _load_json(path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def find_usable_receipt(cwd, args_hash: str, gate_key: str | None, trusted_approvers=None):
    """An approved, unexpired, unused receipt for exactly these arguments, or None."""
    d = approvals_dir(cwd)
    if not d.exists():
        return None, None
    for f in sorted(d.glob("apr_*.json")):
        if f.with_suffix(".used").exists():
            continue
        rec = _load_json(f)
        if rec and check_approval_for(rec, gate_key=gate_key, args_hash=args_hash,
                                      trusted_approvers=trusted_approvers):
            return rec, f
    return None, None


def _save_receipt(cwd, receipt: dict, *, used: bool):
    d = approvals_dir(cwd)
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{receipt['request']['id']}.json"
    f.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
    if used:
        f.with_suffix(".used").write_text(now_iso(), encoding="utf-8")
    return f


def _pending(cwd) -> dict:
    return _load_json(approvals_dir(cwd) / "pending.json")


def _set_pending(cwd, args_hash: str, entry: dict | None) -> None:
    d = approvals_dir(cwd)
    d.mkdir(parents=True, exist_ok=True)
    data = _pending(cwd)
    if entry is None:
        data.pop(args_hash, None)
    else:
        data[args_hash] = entry
    (d / "pending.json").write_text(json.dumps(data, indent=2), encoding="utf-8")


def summarise_action(tool: str, args) -> str:
    """The text an approver reads: the real command or target, not the agent's description."""
    if isinstance(args, dict):
        for k in ("command", "query", "sql", "file_path", "path", "url"):
            if isinstance(args.get(k), str) and args[k].strip():
                return args[k][:2000]
        return f"{tool} " + json.dumps(args, sort_keys=True, default=str)[:2000]
    return f"{tool} {args}"[:2000]


def apply_gate(decision, *, tool: str, args, cwd, session_id: str = "", agent_name: str = "agent",
               wait_seconds: int = 0, client: GateClient | None = None):
    """Turn a guard *deny* into a request for a person's approval.

    Returns the (possibly new) guard Decision. Self-authorization and guard errors are
    never sent for approval. Without a configured Gate (or a pinned Gate key), the
    original decision is returned unchanged.
    """
    from .guard import Decision
    from .recorder import content_hash

    if decision is None or decision.decision != "deny" or str(decision.rule or "").startswith("guard."):
        return decision
    client = client if client is not None else GateClient.from_config()
    if client is None:
        return decision
    first = (decision.reason or "").splitlines()[0] if decision.reason else "perathos guard: blocked"
    if not client.gate_key:
        return Decision("deny", decision.rule, None,
                        f"{first}. Perathos Gate is configured but its key is not pinned; run 'perathos gate login'.")
    ah = content_hash(args)

    pins = trusted_approver_keys()
    rec, path = find_usable_receipt(cwd, ah, client.gate_key, pins)
    if rec is not None:
        path.with_suffix(".used").write_text(now_iso(), encoding="utf-8")
        return Decision("allow", decision.rule, None,
                        f"perathos guard: allowed, approved by {rec['approver'].get('name')} with a passkey at "
                        f"{rec['decided_at']}", approval=rec["receipt_hash"])

    try:
        pend = _pending(cwd).get(ah)
        if pend and parse_iso(pend["expires_at"]) > datetime.now(timezone.utc):
            approval_id, approve_url = pend["id"], pend["approve_url"]
        else:
            import socket
            created = client.request(
                action={"tool": tool, "summary": summarise_action(tool, args), "rule": decision.rule,
                        "detail": first},
                agent={"name": agent_name, "session_id": session_id, "host": socket.gethostname()},
                args_hash=ah)
            approval_id, approve_url = created["id"], created["approve_url"]
            _set_pending(cwd, ah, {"id": approval_id, "approve_url": approve_url, "expires_at": created["expires_at"]})
        st = client.wait_for_decision(approval_id, wait_seconds) if wait_seconds > 0 else client.status(approval_id, 0)
    except GateError as exc:
        return Decision("deny", decision.rule, None, f"{first}. Perathos Gate unreachable ({exc}).")

    status = st.get("status")
    receipt = st.get("receipt")
    if status == "approved" and isinstance(receipt, dict):
        chk = check_approval_for(receipt, gate_key=client.gate_key, args_hash=ah, trusted_approvers=pins)
        _set_pending(cwd, ah, None)
        if not chk:
            _save_receipt(cwd, receipt, used=True)
            return Decision("deny", decision.rule, None, f"{first}. Approval receipt rejected: {chk.error}")
        _save_receipt(cwd, receipt, used=True)
        return Decision("allow", decision.rule, None,
                        f"perathos guard: allowed, approved by {receipt['approver'].get('name')} with a passkey",
                        approval=receipt["receipt_hash"])
    if status == "denied" and isinstance(receipt, dict):
        _set_pending(cwd, ah, None)
        if verify_receipt(receipt, gate_key=client.gate_key):
            _save_receipt(cwd, receipt, used=True)
        who = receipt.get("approver", {}).get("name", "the approver")
        return Decision("deny", decision.rule, None, f"{first}. {who} denied this action.")
    if status == "expired":
        _set_pending(cwd, ah, None)
        return Decision("deny", decision.rule, None, f"{first}. The approval request expired; retry to ask again.")
    return Decision("deny", decision.rule, None,
                    f"{first}. Approval requested from a person: {approve_url} . Retry this exact command "
                    f"after it is approved.")


# --------------------------------------------------------------------------- #
# SDK for any agent or script
# --------------------------------------------------------------------------- #


class ApprovalDenied(GateError):
    pass


class ApprovalTimeout(GateError):
    pass


def require_approval(summary: str, *, tool: str = "custom", args=None, target: str | None = None,
                     detail: str | None = None, agent: str = "sdk", session_id: str = "",
                     wait_seconds: int = 300, ttl_seconds: int = 600, client: GateClient | None = None,
                     on_created=None) -> dict:
    """Block until a person approves this action with a passkey; return the verified receipt.

    Prints the approve link to stderr as soon as the request exists (or passes the created
    request to ``on_created`` instead). Raises ApprovalDenied, ApprovalTimeout, or GateError. Example::

        receipt = require_approval("Wire $5,000 to ACME Ltd", tool="payments.transfer",
                                   args={"to": "ACME Ltd", "amount": 5000})
        do_transfer()
    """
    from .recorder import content_hash
    client = client if client is not None else GateClient.from_config()
    if client is None:
        raise GateError("Perathos Gate is not configured: run 'perathos gate login'")
    if not client.gate_key:
        raise GateError("Gate key is not pinned: run 'perathos gate login'")
    ah = content_hash(args if args is not None else summary)
    created = client.request(action={"tool": tool, "summary": summary, "target": target, "detail": detail},
                             agent={"name": agent, "session_id": session_id}, args_hash=ah, ttl_seconds=ttl_seconds)
    # Surface the approve link at once: without a notifier the requester is the only one who has it.
    if on_created is not None:
        on_created(created)
    else:
        print(f"perathos gate: waiting for approval of {created['id']}; approve at {created['approve_url']}",
              file=sys.stderr, flush=True)
    st = client.wait_for_decision(created["id"], wait_seconds)
    status, receipt = st.get("status"), st.get("receipt")
    if status == "approved" and isinstance(receipt, dict):
        chk = check_approval_for(receipt, gate_key=client.gate_key, args_hash=ah,
                                 trusted_approvers=trusted_approver_keys())
        if not chk:
            raise GateError(f"approval receipt rejected: {chk.error}")
        return receipt
    if status == "denied":
        raise ApprovalDenied(f"denied by {(receipt or {}).get('approver', {}).get('name', 'the approver')}")
    raise ApprovalTimeout(f"no decision within {wait_seconds}s (status {status}); approve at {created['approve_url']}")
