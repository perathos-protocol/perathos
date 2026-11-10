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
from importlib import import_module as _import_module

# Public names are loaded on first use (PEP 562) so that light entry points,
# such as the flight-recorder hooks that run on every agent tool call, do not
# pay for importing the verifier engines. `from perathos import X` and
# `perathos.X` behave exactly as before.
_LAZY = {
    "create_bundle": ".bundle", "sign_bundle": ".bundle", "verify_bundle": ".bundle",
    "BinningCalibrator": ".calibration", "TemperatureCalibrator": ".calibration",
    "expected_calibration_error": ".calibration",
    "HallucinationDetector": ".engines", "SchemaValidator": ".engines", "SymbolicSolver": ".engines",
    "TemporalConsistency": ".engines", "all_engines": ".engines",
    "inspect_bundle": ".inspector",
    "KmsSigner": ".keytrust", "LocalSigner": ".keytrust", "Signer": ".keytrust", "TrustStore": ".keytrust",
    "kid_for": ".keytrust",
    "MultiVerifierPipeline": ".pipeline", "VerificationResult": ".pipeline", "verify_output": ".pipeline",
    "generate_keypair": ".signing", "verify_signature": ".signing",
    "VerdictRecord": ".verdict",
    "ClaimEntailmentVerifier": ".verifiers", "CrossExaminer": ".verifiers", "VerificationContext": ".verifiers",
    "Verifier": ".verifiers", "default_verifiers": ".verifiers",
}
# Short public aliases: the SAME function objects as the long names.
_ALIASES = {"prove": "create_bundle", "sign": "sign_bundle", "verify": "verify_bundle", "inspect": "inspect_bundle"}


def __getattr__(name: str):
    target = _ALIASES.get(name, name)
    module = _LAZY.get(target)
    if module is None:
        raise AttributeError(f"module 'perathos' has no attribute {name!r}")
    value = getattr(_import_module(module, __name__), target)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY) | set(_ALIASES))


__version__ = "1.3.1"

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
    # key management & trust anchoring
    "LocalSigner",
    "KmsSigner",
    "Signer",
    "TrustStore",
    "kid_for",
    # multi-verifier pipeline
    "verify_output",
    "MultiVerifierPipeline",
    "VerificationResult",
    "VerificationContext",
    "VerdictRecord",
    "Verifier",
    "CrossExaminer",
    "ClaimEntailmentVerifier",
    "default_verifiers",
    # real verifier engines
    "SymbolicSolver",
    "HallucinationDetector",
    "SchemaValidator",
    "TemporalConsistency",
    "all_engines",
    # calibration (real-confidence honesty)
    "TemperatureCalibrator",
    "BinningCalibrator",
    "expected_calibration_error",
]
