"""Ed25519 cryptographic signing and verification.

Provides keypair generation and Ed25519-based signing/verification of
integrity hashes. Uses PyNaCl (libsodium) for constant-time operations
and protection against common implementation pitfalls.
"""
import nacl.encoding
import nacl.exceptions
import nacl.signing


def generate_keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 keypair.

    Returns:
        A tuple (signing_key_hex, verify_key_hex) where each is a
        64-character lowercase hex-encoded string representing the
        32-byte raw key material.
    """
    sk = nacl.signing.SigningKey.generate()
    sk_hex = sk.encode(nacl.encoding.HexEncoder).decode()
    vk_hex = sk.verify_key.encode(nacl.encoding.HexEncoder).decode()
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

    sk = nacl.signing.SigningKey(signing_key_hex, encoder=nacl.encoding.HexEncoder)
    signed = sk.sign(bytes.fromhex(integrity_hash))
    return {
        "algorithm": "ed25519",
        "verify_key": sk.verify_key.encode(nacl.encoding.HexEncoder).decode(),
        "signature": signed.signature.hex(),
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
        vk = nacl.signing.VerifyKey(
            verify_key, encoder=nacl.encoding.HexEncoder
        )
        vk.verify(bytes.fromhex(integrity_hash), bytes.fromhex(signature_hex))
        return True, ""
    except nacl.exceptions.BadSignatureError:
        return False, "ERR_BAD_SIGNATURE"
    except Exception as exc:
        return False, f"ERR_SIGNATURE_INVALID:{exc}"
