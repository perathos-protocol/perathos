"""Perathos — cryptographic proof layer for AI outputs."""
from .bundle import create_bundle, sign_bundle, verify_bundle
from .inspector import inspect_bundle
from .signing import generate_keypair, verify_signature

__version__ = "0.1.0"

# Public API aliases for user-facing functions
prove = create_bundle
verify = verify_bundle
sign = sign_bundle
inspect = inspect_bundle

__all__ = [
    # Low-level functions
    "create_bundle",
    "sign_bundle",
    "verify_bundle",
    "inspect_bundle",
    "generate_keypair",
    "verify_signature",
    # High-level aliases
    "prove",
    "verify",
    "sign",
    "inspect",
]
