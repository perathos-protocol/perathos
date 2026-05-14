import nacl.encoding
import nacl.exceptions
import nacl.signing


def generate_keypair() -> tuple[str, str]:
    """Return (signing_key_hex, verify_key_hex) for a fresh Ed25519 keypair."""
    sk = nacl.signing.SigningKey.generate()
    sk_hex = sk.encode(nacl.encoding.HexEncoder).decode()
    vk_hex = sk.verify_key.encode(nacl.encoding.HexEncoder).decode()
    return sk_hex, vk_hex


def sign_hash(integrity_hash: str, signing_key_hex: str) -> dict:
    """
    Sign the raw bytes of integrity_hash with Ed25519.

    We sign bytes.fromhex(integrity_hash) — the 32 raw bytes — rather than
    the hex string, because the hash bytes are the canonical representation
    and this is consistent with how other tools (OpenSSH, age) handle digests.
    """
    sk = nacl.signing.SigningKey(signing_key_hex, encoder=nacl.encoding.HexEncoder)
    signed = sk.sign(bytes.fromhex(integrity_hash))
    return {
        "algorithm": "ed25519",
        "verify_key": sk.verify_key.encode(nacl.encoding.HexEncoder).decode(),
        "signature": signed.signature.hex(),
    }


def verify_signature(integrity_hash: str, provider_signature: dict) -> tuple[bool, str]:
    """Return (True, "") or (False, "ERR_CODE")."""
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
