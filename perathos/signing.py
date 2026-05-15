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
    """
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
    try:
        vk = nacl.signing.VerifyKey(
            provider_signature["verify_key"], encoder=nacl.encoding.HexEncoder
        )
        vk.verify(bytes.fromhex(integrity_hash), bytes.fromhex(provider_signature["signature"]))
        return True, ""
    except nacl.exceptions.BadSignatureError:
        return False, "ERR_BAD_SIGNATURE"
    except KeyError as exc:
        return False, f"ERR_MISSING_SIG_FIELD:{exc}"
    except Exception as exc:
        return False, f"ERR_SIGNATURE_INVALID:{exc}"
