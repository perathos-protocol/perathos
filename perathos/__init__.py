"""Perathos — cryptographic proof layer for AI outputs.

Provides a clean Python API for creating, signing, and verifying tamper-evident
VRL Proof Bundles on AI-generated content. Each bundle captures the input hash,
output hash, execution trace, and optional cryptographic signature.

Example:
    >>> from perathos import prove, verify, sign
    >>> bundle = prove("The capital of France is Paris.")
    >>> bundle = sign(bundle)  # attach Ed25519 signature
    >>> valid, err = verify(bundle)
    >>> print(valid)  # True
"""
from .bundle import create_bundle, sign_bundle, verify_bundle
from .inspector import inspect_bundle
from .signing import generate_keypair, verify_signature

__version__ = "0.1.0"

# Public API aliases for library users
prove = create_bundle
prove.__doc__ = """Build a VRL Proof Bundle for a given AI output. Alias for create_bundle().

Constructs a tamper-evident bundle by hashing the input and output,
capturing execution metadata in a trace, and computing an integrity root hash.
The bundle_id is derived deterministically via UUIDv5 from the integrity hash,
so it is reconstructable offline without any state.

Args:
    output_text: The AI-generated text to prove (e.g., model completion).
    input_text: Original prompt or request that produced output_text.
        Defaults to empty string for prove-from-output-only use cases.

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
"""

sign = sign_bundle
sign.__doc__ = """Attach an Ed25519 provider_signature over integrity_hash. Alias for sign_bundle().

Computes an Ed25519 signature on the raw bytes of integrity_hash and
adds it to the bundle as a provider_signature field. Does not mutate
the input bundle; returns a new dict with the signature attached.

Args:
    bundle: A bundle dict from create_bundle() (or compatible structure).
    signing_key_hex: 64-character hex-encoded Ed25519 signing key.

Returns:
    A new dict with all fields from bundle plus a "provider_signature" field containing:
        - algorithm: "ed25519"
        - verify_key: 64-character hex-encoded public key
        - signature: 128-character hex-encoded signature bytes
"""

verify = verify_bundle
verify.__doc__ = """Recompute all hashes from stored data and check they match. Alias for verify_bundle().

Verifies the integrity chain: _trace → trace_hash → integrity_hash → bundle_id.
Does not re-hash the original input/output text (those are gone); only checks
that the stored hashes are self-consistent and form a valid chain.

Args:
    bundle: A bundle dict from create_bundle() (optionally with signature).

Returns:
    A tuple (valid, error_code) where:
        - valid is True and error_code is "" on successful verification.
        - valid is False and error_code is a string like "ERR_TRACE_HASH_MISMATCH"
          or "ERR_MISSING_TRACE" on any failure. Check for 'ERR' substring to
          detect invalid bundles.
"""

inspect = inspect_bundle
inspect.__doc__ = """Pretty-print a bundle in human-readable form. Alias for inspect_bundle().

Automatically selects between rich-styled output (if rich is installed and
terminal supports Unicode) and plain-text fallback. Displays bundle metadata,
hash chain, and trace steps with appropriate styling.

Args:
    bundle: Bundle dict from create_bundle() or loaded via storage.load_bundle().
"""

__all__ = [
    "prove",
    "verify",
    "sign",
    "inspect",
    "create_bundle",
    "sign_bundle",
    "verify_bundle",
    "inspect_bundle",
    "generate_keypair",
    "verify_signature",
]
