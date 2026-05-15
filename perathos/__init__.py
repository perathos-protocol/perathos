"""Perathos — cryptographic proof layer for AI outputs."""
from .bundle import create_bundle, sign_bundle, verify_bundle
from .inspector import inspect_bundle
from .signing import generate_keypair, verify_signature

__version__ = "0.1.0"

__all__ = [
    "create_bundle",
    "sign_bundle",
    "verify_bundle",
    "inspect_bundle",
    "generate_keypair",
    "verify_signature",
]
