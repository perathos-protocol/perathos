"""VRL Proof Bundle creation and verification logic.

Handles the construction of tamper-evident bundles that capture the hash chain
from input/output through execution trace to the integrity root, plus optional
Ed25519 cryptographic signatures. All hashes are SHA-256 and deterministically
encoded to ensure offline verifiability.
"""
import hashlib
import uuid
from datetime import datetime, timezone

from .canonical import canonical_bytes

# Deterministic namespace: all Perathos bundle IDs live under this UUID.
# Derived itself via uuid5 so it's auditable, not magic.
PERATHOS_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://perathos.io/vrl/v1")

# The model identity descriptor — in production this would encode model weights
# fingerprint, version, and serving config.
_MODEL_DESCRIPTOR = "perathos-demo-model:sha256-deterministic:v1"


def _sha256(data: bytes) -> str:
    """Compute SHA-256 digest of bytes and return as hex string.

    Used internally for all hash operations in the bundle: input, output,
    trace, and integrity payload. The result is always a 64-character
    lowercase hex string suitable for use in bundles and hashing chains.

    Args:
        data: Bytes to hash.

    Returns:
        Lowercase hex-encoded SHA-256 digest (64 characters).

    Examples:
        _sha256(b"hello") → "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        _sha256(b"") → "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    """
    return hashlib.sha256(data).hexdigest()


def ai_id() -> str:
    """Stable AI identity: SHA-256 of the model descriptor string.

    Returns the same hash across all invocations and machines, since it
    derives from a fixed model descriptor string. In production, this would
    reflect actual model weights fingerprint and serving configuration,
    enabling verifiers to confirm which model produced a given output.

    The model descriptor is a colon-separated string:
        <name>:<proof_system>:<version>
    Example: "openai-gpt4-serving:sha256-deterministic:v20240101"

    Returns:
        Lowercase hex-encoded SHA-256 (64 characters) of the model descriptor.
        In production, this would reflect actual model weights and serving config.

    Examples:
        ai_id() → "7f9c2ba4e88fb81860ea5e70f527f31f..." (deterministic, always same)
    """
    return _sha256(_MODEL_DESCRIPTOR.encode("utf-8"))


def create_bundle(output_text: str, input_text: str = "", verification: dict | None = None) -> dict:
    """Build a VRL Proof Bundle for a given AI output.

    Constructs a tamper-evident bundle by hashing the input and output,
    capturing execution metadata in a trace, and computing an integrity root
    hash. The bundle_id is derived deterministically via UUIDv5 from the
    integrity hash, so it is reconstructable offline without any state.

    Args:
        output_text: The AI-generated text to prove (e.g., model completion).
            Must be a string (empty string is allowed).
        input_text: Original prompt or request that produced output_text.
            Defaults to empty string for prove-from-output-only use cases.
            Must be a string.
        verification: Optional verification block (verdict records + aggregate
            verdict) produced by the multi-verifier pipeline. When present, its
            digest is folded into integrity_hash so the verdicts are signed and
            tamper-evident; stripping or altering them breaks verification.

    Returns:
        A dictionary containing:
            - bundle_id: UUIDv5 derived from integrity_hash.
            - ai_id: SHA-256 of the model descriptor.
            - input_hash: SHA-256 of input_text.
            - output_hash: SHA-256 of output_text.
            - trace_hash: SHA-256 of execution metadata.
            - integrity_hash: SHA-256 of the canonical integrity payload.
            - issued_at: ISO 8601 timestamp (UTC).
            - proof_system: String identifier for the hash scheme ("sha256-deterministic").
            - _trace: Verbatim execution metadata dict (used by verifiers).

    Raises:
        ValueError: If output_text is not a string, or if input_text is not a string.
        TypeError: If output_text or input_text have wrong type.
    """
    if not isinstance(output_text, str):
        raise ValueError(
            f"output_text must be a string, got {type(output_text).__name__}"
        )
    if not isinstance(input_text, str):
        raise ValueError(
            f"input_text must be a string, got {type(input_text).__name__}"
        )
    if verification is not None and not isinstance(verification, dict):
        raise ValueError(
            f"verification must be a dict or None, got {type(verification).__name__}"
        )

    issued_at = datetime.now(timezone.utc).isoformat()
    proof_system = "sha256-deterministic"

    input_hash = _sha256(input_text.encode("utf-8"))
    output_hash = _sha256(output_text.encode("utf-8"))

    # Trace captures execution metadata needed to reproduce / audit the run.
    # Hashed separately so it can grow without breaking the integrity chain.
    trace = {
        "model_descriptor": _MODEL_DESCRIPTOR,
        "proof_system": proof_system,
        "input_length": len(input_text),
        "output_length": len(output_text),
    }
    trace_hash = _sha256(canonical_bytes(trace))

    model_ai_id = ai_id()

    # Integrity payload — the tamper-evident root. Every semantically
    # significant field is included; changing any one of them rotates the
    # integrity_hash and therefore the bundle_id.
    integrity_payload = {
        "ai_id": model_ai_id,
        "input_hash": input_hash,
        "issued_at": issued_at,
        "output_hash": output_hash,
        "proof_system": proof_system,
        "trace_hash": trace_hash,
    }
    # Bind the verification block (if any) into the integrity root. Including
    # verification_hash only when verification is present keeps bundles without
    # verification byte-for-byte backward compatible, and any later attempt to
    # add, remove, or edit the block flips this recomputation -> tamper detected.
    if verification is not None:
        integrity_payload["verification_hash"] = _sha256(canonical_bytes(verification))
    integrity_hash = _sha256(canonical_bytes(integrity_payload))

    # UUIDv5: deterministic, reconstructable from integrity_hash alone.
    bundle_id = str(uuid.uuid5(PERATHOS_NAMESPACE, integrity_hash))

    bundle = {
        "bundle_id": bundle_id,
        "proof_system": proof_system,
        "issued_at": issued_at,
        "ai_id": model_ai_id,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "trace_hash": trace_hash,
        "integrity_hash": integrity_hash,
        # _trace stored verbatim so verifiers can recompute trace_hash offline.
        "_trace": trace,
    }
    if verification is not None:
        # Stored verbatim so a consumer can recompute verification_hash offline.
        bundle["verification"] = verification
    return bundle


def sign_bundle(bundle: dict, signing_key_hex: str) -> dict:
    """Attach an Ed25519 provider_signature over integrity_hash.

    Computes an Ed25519 signature on the raw bytes of integrity_hash and
    adds it to the bundle as a provider_signature field. Does not mutate
    the input bundle; returns a new dict with the signature attached.

    Args:
        bundle: A bundle dict from create_bundle() (or compatible structure).
            Must be a dict and must contain the 'integrity_hash' field.
        signing_key_hex: 64-character hex-encoded Ed25519 signing key.
            Must be a string containing exactly 64 hex characters (0-9, a-f).

    Returns:
        A new dict with all fields from bundle plus a "provider_signature" field:
            - algorithm: "ed25519"
            - verify_key: 64-character hex-encoded public key
            - signature: 128-character hex-encoded signature bytes

    Raises:
        TypeError: If bundle is not a dict or signing_key_hex is not a string.
        KeyError: If bundle does not contain the 'integrity_hash' field.
        ValueError: If signing_key_hex is not a valid 64-character hex string.
    """
    if not isinstance(bundle, dict):
        raise TypeError(f"bundle must be a dict, got {type(bundle).__name__}")
    from .keytrust import LocalSigner, Signer  # local import to avoid cycles
    is_signer = isinstance(signing_key_hex, Signer)
    if not is_signer and not isinstance(signing_key_hex, str):
        raise TypeError(
            f"signing_key_hex must be a string or a Signer, got {type(signing_key_hex).__name__}"
        )
    if "integrity_hash" not in bundle:
        raise KeyError("bundle must contain 'integrity_hash' field")

    if is_signer:
        signer = signing_key_hex
    else:
        if len(signing_key_hex) != 64:
            raise ValueError(
                f"signing_key_hex must be exactly 64 hex characters, got {len(signing_key_hex)}"
            )
        if any(c not in "0123456789abcdef" for c in signing_key_hex):
            raise ValueError(
                f"signing_key_hex must contain only lowercase hex characters (0-9, a-f), got: {signing_key_hex}"
            )
        signer = LocalSigner.from_hex(signing_key_hex)

    from .signing import sign_hash_with_signer
    sig = sign_hash_with_signer(bundle["integrity_hash"], signer)
    return {**bundle, "provider_signature": sig}


def verify_bundle(bundle: dict, expected_verify_key: str | None = None, trust_store=None) -> tuple[bool, str]:
    """Recompute all hashes from stored data and check they match.

    Verifies the integrity chain: _trace → trace_hash → integrity_hash → bundle_id,
    and — if the bundle carries a provider_signature — that the Ed25519 signature
    validates over integrity_hash. Does not re-hash the original input/output text
    (those are gone); only checks that the stored hashes are self-consistent and
    form a valid chain.

    Args:
        bundle: A bundle dict from create_bundle() (optionally with signature).
        expected_verify_key: If given, a signed bundle is only accepted when its
            provider_signature.verify_key equals this 64-char hex public key. This
            pins provenance: the signature itself only proves *some* key signed the
            hash, and verify_key lives outside integrity_hash, so without pinning an
            attacker can strip the signature and re-sign with their own key.

    Returns:
        A tuple (valid, error_code) where:
            - valid is True and error_code is "" on successful verification.
            - valid is False and error_code is a string like "ERR_TRACE_HASH_MISMATCH"
              on any failure. Check for 'ERR' substring to detect invalid bundles.
    """
    try:
        trace = bundle.get("_trace")
        if trace is None:
            return False, "ERR_MISSING_TRACE"

        # Step 1: trace integrity
        if _sha256(canonical_bytes(trace)) != bundle["trace_hash"]:
            return False, "ERR_TRACE_HASH_MISMATCH"

        # Step 2: integrity root
        integrity_payload = {
            "ai_id": bundle["ai_id"],
            "input_hash": bundle["input_hash"],
            "issued_at": bundle["issued_at"],
            "output_hash": bundle["output_hash"],
            "proof_system": bundle["proof_system"],
            "trace_hash": bundle["trace_hash"],
        }
        # The verification block is bound into integrity_hash iff it is present
        # (see create_bundle). Recompute symmetrically so that adding, removing,
        # or editing the verdicts is detected as a hash mismatch.
        verification = bundle.get("verification")
        if verification is not None:
            integrity_payload["verification_hash"] = _sha256(canonical_bytes(verification))
        if _sha256(canonical_bytes(integrity_payload)) != bundle["integrity_hash"]:
            return False, "ERR_INTEGRITY_HASH_MISMATCH"

        # Step 3: bundle_id derivation
        expected_id = str(uuid.uuid5(PERATHOS_NAMESPACE, bundle["integrity_hash"]))
        if expected_id != bundle["bundle_id"]:
            return False, "ERR_BUNDLE_ID_MISMATCH"

        # Step 4: signature. A bundle that carries a provider_signature must NOT
        # pass verification if that signature does not validate — otherwise the
        # public verify() reports a forged signature as valid.
        sig = bundle.get("provider_signature")
        if sig is not None:
            from .signing import verify_signature  # local import avoids a cycle
            sig_valid, sig_err = verify_signature(bundle["integrity_hash"], sig)
            if not sig_valid:
                return False, sig_err
            # Step 5: optional signer pinning (provenance).
            if expected_verify_key is not None and sig.get("verify_key") != expected_verify_key:
                return False, "ERR_UNEXPECTED_SIGNER"
            # Step 6: optional trust-anchor check — the signer's key must be one
            # the consumer has explicitly trusted (by derived kid), not just any
            # key the bundle embeds. Scales signer pinning to many keys via JWKS.
            if trust_store is not None:
                from .keytrust import kid_for
                vk_bytes = bytes.fromhex(sig["verify_key"])
                if trust_store.get(kid_for(vk_bytes)) != vk_bytes:
                    return False, "ERR_UNTRUSTED_SIGNER"

        return True, ""

    except KeyError as exc:
        return False, f"ERR_MISSING_FIELD:{exc}"
    except (TypeError, ValueError) as exc:
        # A hostile/malformed bundle (e.g. _trace with mixed-type keys that
        # json.dumps(sort_keys=True) cannot order) must return an error, not
        # crash a verifier that is documented to return (False, error_code).
        return False, f"ERR_MALFORMED_BUNDLE:{exc}"
