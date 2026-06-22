"""Ed25519 cryptographic signing and verification.

Provides keypair generation and Ed25519-based signing/verification of
integrity hashes. Uses the `cryptography` library (pyca) for constant-time
Ed25519 — the canonical crypto backend across the VRL stack.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 keypair.

    Returns:
        A tuple (signing_key_hex, verify_key_hex) where each is a
        64-character lowercase hex-encoded string representing the
        32-byte raw key material.
    """
    sk = Ed25519PrivateKey.generate()
    sk_hex = sk.private_bytes_raw().hex()
    vk_hex = sk.public_key().public_bytes_raw().hex()
    return sk_hex, vk_hex


def _validate_hex_hash(value: str, name: str, length: int = 64) -> None:
    """Validate that a value is a valid hex string of exact length.

    Args:
        value: The string to validate.
        name: The name of the parameter (for error messages).
        length: Expected length in characters (default 64 for SHA-256 hex).

    Raises:
        ValueError: If value is not exactly `length` hex characters.
    """
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string, got {type(value).__name__}")
    if len(value) != length:
        raise ValueError(
            f"{name} must be exactly {length} hex characters, got {len(value)}"
        )
    # Strict, canonical hex only: lowercase 0-9a-f. int(value, 16) would wrongly
    # accept uppercase, a leading "0x", and surrounding whitespace — none of
    # which are canonical SHA-256/key hex and any of which break byte-equality
    # comparisons or bytes.fromhex() downstream.
    if any(c not in "0123456789abcdef" for c in value):
        raise ValueError(
            f"{name} must be valid lowercase hex characters (0-9, a-f), got: {value}"
        )


def sign_hash(integrity_hash: str, signing_key_hex: str) -> dict:
    """Sign the raw bytes of an integrity_hash with Ed25519.

    Signs bytes.fromhex(integrity_hash) — the 32 raw bytes — rather than
    the hex string, because the hash bytes are the canonical representation
    and this is consistent with how other tools (OpenSSH, age) handle digests.

    Args:
        integrity_hash: 64-character hex-encoded SHA-256 digest.
        signing_key_hex: 64-character hex-encoded Ed25519 signing key.

    Returns:
        A dictionary with signature metadata:
            - algorithm: "ed25519"
            - verify_key: 64-character hex-encoded public key (derived from signing_key)
            - signature: 128-character hex-encoded signature bytes

    Raises:
        ValueError: If integrity_hash or signing_key_hex are not valid 64-char hex strings.
    """
    _validate_hex_hash(integrity_hash, "integrity_hash", 64)
    _validate_hex_hash(signing_key_hex, "signing_key_hex", 64)

    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
    signature = sk.sign(bytes.fromhex(integrity_hash))
    return {
        "algorithm": "ed25519",
        "verify_key": sk.public_key().public_bytes_raw().hex(),
        "signature": signature.hex(),
    }


def sign_hash_with_signer(integrity_hash: str, signer) -> dict:
    """Sign integrity_hash with a keytrust.Signer (Local or KMS-backed).

    Produces the SAME provider_signature shape as sign_hash() — a KMS-signed
    bundle is indistinguishable in format from a locally-signed one and verifies
    via verify_signature() unchanged. The signer's private key may live in a KMS.
    """
    _validate_hex_hash(integrity_hash, "integrity_hash", 64)
    signature = signer.sign(bytes.fromhex(integrity_hash))
    return {
        "algorithm": signer.alg,
        "verify_key": signer.public_key.hex(),
        "signature": signature.hex(),
    }


def verify_signature(integrity_hash: str, provider_signature: dict) -> tuple[bool, str]:
    """Verify an Ed25519 signature over an integrity_hash.

    Uses the public verify_key stored in the provider_signature dict to
    verify that the signature is valid for the given hash. Constant-time
    comparison prevents timing attacks.

    Args:
        integrity_hash: 64-character hex-encoded SHA-256 digest (what was signed).
        provider_signature: Dict with keys "verify_key" (64-char hex) and
            "signature" (128-char hex) from sign_hash().

    Returns:
        A tuple (valid, error_code) where:
            - valid is True and error_code is "" if signature is valid.
            - valid is False and error_code is a string like "ERR_BAD_SIGNATURE"
              or "ERR_MISSING_SIG_FIELD" if verification fails.
    """
    if not isinstance(provider_signature, dict):
        return False, "ERR_MISSING_SIG_FIELD:provider_signature must be a dict"

    # Bind verification to the declared algorithm: only Ed25519 is supported, and
    # we refuse to display/accept a signature whose algorithm field claims
    # anything else (prevents algorithm-confusion / spoofing of the field).
    if provider_signature.get("algorithm") != "ed25519":
        return False, "ERR_UNSUPPORTED_ALGORITHM"

    try:
        _validate_hex_hash(integrity_hash, "integrity_hash", 64)
    except ValueError as exc:
        return False, f"ERR_INVALID_HASH:{exc}"

    try:
        verify_key = provider_signature["verify_key"]
        _validate_hex_hash(verify_key, "verify_key", 64)
    except ValueError as exc:
        return False, f"ERR_INVALID_VERIFY_KEY:{exc}"
    except KeyError as exc:
        return False, f"ERR_MISSING_SIG_FIELD:{exc}"

    try:
        signature_hex = provider_signature["signature"]
        # Strict, canonical hex (lowercase 0-9a-f, exactly 128 chars) — same
        # policy as integrity_hash/verify_key. int(x, 16) would tolerate
        # uppercase/0x, permitting multiple valid serializations of one signature.
        _validate_hex_hash(signature_hex, "signature", 128)
    except ValueError as exc:
        return False, f"ERR_INVALID_SIGNATURE:{exc}"
    except KeyError as exc:
        return False, f"ERR_MISSING_SIG_FIELD:{exc}"

    try:
        vk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(verify_key))
        vk.verify(bytes.fromhex(signature_hex), bytes.fromhex(integrity_hash))
        return True, ""
    except InvalidSignature:
        return False, "ERR_BAD_SIGNATURE"
    except Exception as exc:
        return False, f"ERR_SIGNATURE_INVALID:{exc}"
