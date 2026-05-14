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
    return hashlib.sha256(data).hexdigest()


def ai_id() -> str:
    """Stable AI identity: SHA-256 of the model descriptor string."""
    return _sha256(_MODEL_DESCRIPTOR.encode("utf-8"))


def create_bundle(output_text: str, input_text: str = "") -> dict:
    """
    Build a VRL Proof Bundle for a given AI output.

    input_text defaults to "" for the prove-from-output-only CLI use case.
    In a real pipeline, pass the prompt/request that produced output_text.
    """
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
    integrity_hash = _sha256(canonical_bytes(integrity_payload))

    # UUIDv5: deterministic, reconstructable from integrity_hash alone.
    bundle_id = str(uuid.uuid5(PERATHOS_NAMESPACE, integrity_hash))

    return {
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


def sign_bundle(bundle: dict, signing_key_hex: str) -> dict:
    """
    Attach an Ed25519 provider_signature over integrity_hash and return
    the updated bundle. Does not mutate the original dict.
    """
    from .signing import sign_hash  # local import to avoid circular deps
    sig = sign_hash(bundle["integrity_hash"], signing_key_hex)
    return {**bundle, "provider_signature": sig}


def verify_bundle(bundle: dict) -> tuple[bool, str]:
    """
    Recompute all hashes from stored data and check they match.

    Returns (True, "") on success or (False, "ERR_CODE") on any failure.
    Does not re-hash the original input/output text — those are gone.
    Verifies the chain: _trace → trace_hash → integrity_hash → bundle_id.
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
        if _sha256(canonical_bytes(integrity_payload)) != bundle["integrity_hash"]:
            return False, "ERR_INTEGRITY_HASH_MISMATCH"

        # Step 3: bundle_id derivation
        expected_id = str(uuid.uuid5(PERATHOS_NAMESPACE, bundle["integrity_hash"]))
        if expected_id != bundle["bundle_id"]:
            return False, "ERR_BUNDLE_ID_MISMATCH"

        return True, ""

    except KeyError as exc:
        return False, f"ERR_MISSING_FIELD:{exc}"
