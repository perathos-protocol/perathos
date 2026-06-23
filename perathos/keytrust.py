"""Production key management for Perathos signing: KMS-ready signers + a trust
anchor (TrustStore / JWKS).

This is the canonical key-trust layer for the VRL core. It folds the strongest
parts of the gateway's signing model into perathos WITHOUT changing the bundle
signature format, so existing signed bundles keep verifying:

- a pluggable **Signer** — `LocalSigner` (in-process key, the default) and
  `KmsSigner` (the private key never leaves a KMS/HSM; the cloud call is
  injected, so it is cloud-agnostic and testable);
- a stable **key id (kid)** derived from the public key;
- a **TrustStore** — trusted public keys by kid, exportable as JWKS — so a
  consumer verifies against keys it has explicitly trusted rather than whatever
  key a bundle embeds (which an attacker could swap and re-sign). This is the
  scalable answer to "pin the signer out of band" from the threat model.

Signing still covers exactly `bytes.fromhex(integrity_hash)` and emits the same
`{algorithm, verify_key, signature}` block, so a KMS-signed bundle is
byte-identical in shape to a locally-signed one and verifies the same way. The
kid is *derived* from the embedded verify_key, never trusted from the bundle.

Uses the `cryptography` library (pyca) — the same Ed25519 backend as
perathos.signing and the gateway, so signers are shareable across the stack.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from abc import ABC, abstractmethod
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALG = "ed25519"


def kid_for(public_raw: bytes) -> str:
    """A stable key id derived from the raw public key (matches the gateway)."""
    return "ed25519-" + hashlib.sha256(public_raw).hexdigest()[:16]


# ── signers ──────────────────────────────────────────────────────────────────

class Signer(ABC):
    """Signs a payload; carries its public key, key id, and algorithm."""

    alg: str = ALG
    key_id: str
    public_key: bytes  # raw 32-byte Ed25519 public key

    @abstractmethod
    def sign(self, payload: bytes) -> bytes: ...

    def public_key_hex(self) -> str:
        return self.public_key.hex()


class LocalSigner(Signer):
    """Signs with an in-process Ed25519 key. The default; for production use
    KmsSigner so the private key never leaves a KMS/HSM."""

    def __init__(self, signing_key: Ed25519PrivateKey, *, key_id: str | None = None) -> None:
        self._sk = signing_key
        self.public_key = signing_key.public_key().public_bytes_raw()
        self.key_id = key_id or kid_for(self.public_key)

    def sign(self, payload: bytes) -> bytes:
        return self._sk.sign(payload)

    @classmethod
    def generate(cls, *, key_id: str | None = None) -> "LocalSigner":
        return cls(Ed25519PrivateKey.generate(), key_id=key_id)

    @classmethod
    def from_hex(cls, signing_key_hex: str, *, key_id: str | None = None) -> "LocalSigner":
        if len(signing_key_hex) != 64 or any(c not in "0123456789abcdef" for c in signing_key_hex):
            raise ValueError("signing_key_hex must be 64 lowercase hex characters")
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex)), key_id=key_id)


class KmsSigner(Signer):
    """Production signer whose private key never leaves a KMS/HSM.

    The KMS call is INJECTED (`sign_fn`) so this is cloud-agnostic and testable:
    in deployment wire `sign_fn` to AWS KMS `Sign` / GCP KMS `asymmetricSign` for
    an Ed25519 key, and pass the key's raw public bytes + id from the KMS
    metadata. The private key is never materialized in this process.
    """

    def __init__(self, *, key_id: str, public_key: bytes,
                 sign_fn: Callable[[bytes], bytes], alg: str = ALG) -> None:
        self.key_id = key_id
        self.public_key = public_key
        self.alg = alg
        self._sign_fn = sign_fn

    def sign(self, payload: bytes) -> bytes:
        return self._sign_fn(payload)


def coerce_signer(signer_or_key: Any) -> Signer:
    """Accept a Signer or a 64-char hex signing key, return a Signer."""
    if isinstance(signer_or_key, Signer):
        return signer_or_key
    if isinstance(signer_or_key, str):
        return LocalSigner.from_hex(signer_or_key)
    raise TypeError("expected a Signer or a 64-hex signing key")


# ── trust store ──────────────────────────────────────────────────────────────

class TrustStore:
    """The trust anchor: trusted public keys by kid. A consumer verifies a
    bundle against keys it has explicitly trusted (distributable as JWKS), not
    whatever key the bundle carries — so an attacker cannot swap the key."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def add(self, kid: str, public_raw: bytes) -> "TrustStore":
        existing = self._keys.get(kid)
        if existing is not None and existing != public_raw:
            raise ValueError(f"trust store already has a different key for kid {kid!r}")
        self._keys[kid] = public_raw
        return self

    def add_public_key(self, public_raw: bytes) -> "TrustStore":
        return self.add(kid_for(public_raw), public_raw)

    def add_signer(self, signer: Signer) -> "TrustStore":
        return self.add(signer.key_id, signer.public_key)

    def get(self, kid: str) -> bytes | None:
        return self._keys.get(kid)

    def trusts(self, public_raw: bytes) -> bool:
        return self._keys.get(kid_for(public_raw)) == public_raw

    def to_jwks(self) -> dict[str, Any]:
        return {"keys": [
            {"kty": "OKP", "crv": "Ed25519", "kid": kid,
             "x": base64.urlsafe_b64encode(pk).rstrip(b"=").decode("ascii")}
            for kid, pk in self._keys.items()
        ]}

    @classmethod
    def from_jwks(cls, jwks: dict[str, Any]) -> "TrustStore":
        """Build a trust store from a JWKS, validating every entry.

        A JWKS may come from a partner/endpoint, so malformed input must fail
        with a clear error — never crash, never silently trust junk. Each key
        must be an OKP/Ed25519 entry whose `x` is strict base64url decoding to
        exactly 32 bytes, and whose `kid` matches the perathos-derived kid
        (`kid_for(x)`). A mismatched kid is rejected here rather than becoming an
        inert entry: it signals a tampered or incompatible JWKS.
        """
        if not isinstance(jwks, dict):
            raise ValueError("JWKS must be a JSON object")
        keys = jwks.get("keys", [])
        if not isinstance(keys, list):
            raise ValueError("JWKS 'keys' must be a list")
        store = cls()
        for i, k in enumerate(keys):
            if not isinstance(k, dict):
                raise ValueError(f"JWKS key #{i} must be an object")
            kid, x = k.get("kid"), k.get("x")
            if not isinstance(kid, str) or not isinstance(x, str):
                raise ValueError(f"JWKS key #{i} must have string 'kid' and 'x'")
            pad = "=" * (-len(x) % 4)
            try:
                raw = base64.b64decode(x + pad, altchars="-_", validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(f"JWKS key #{i} has invalid base64url 'x': {exc}") from exc
            if len(raw) != 32:
                raise ValueError(f"JWKS key #{i} 'x' is not a 32-byte Ed25519 key")
            derived = kid_for(raw)
            if kid != derived:
                raise ValueError(
                    f"JWKS key #{i} kid {kid!r} does not match its key (derived {derived!r})"
                )
            store.add(derived, raw)
        return store


def verify_raw_signature(public_raw: bytes, message: bytes, signature: bytes) -> bool:
    """Low-level Ed25519 verify against a raw public key."""
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
