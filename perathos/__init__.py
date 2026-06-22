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
from .pipeline import (
    MultiVerifierPipeline,
    VerificationResult,
    verify_output,
)
from .signing import generate_keypair, verify_signature
from .verdict import VerdictRecord
from .verifiers import (
    ClaimEntailmentVerifier,
    CrossExaminer,
    VerificationContext,
    Verifier,
    default_verifiers,
)

__version__ = "0.1.0"

# Public API aliases for library users. These are the SAME function objects as
# create_bundle/sign_bundle/verify_bundle/inspect_bundle — deliberately not
# reassigning __doc__ here, because doing so would clobber the underlying
# functions' own docstrings (an alias shares the object, not a copy).
prove = create_bundle
sign = sign_bundle
verify = verify_bundle
inspect = inspect_bundle

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
]
