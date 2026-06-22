"""Deterministic canonical JSON encoding for tamper-evident hashing.

Provides a stable JSON representation where key order and formatting are
fixed, enabling reproducible hashes across independent verifiers. This is
critical for Perathos because bundles must be verifiable offline: the same
input dict must always produce identical bytes, regardless of Python version,
platform, or execution order. Without canonical encoding, an attacker could
reorder keys or change whitespace to produce a different hash while keeping
the same logical dict.

Why determinism matters:
  - Bundle integrity relies on hashing dicts (trace, integrity payload).
  - If two Python processes hash the same dict differently, one verifier
    will reject a valid bundle (false negative) or accept a tampered one
    (false positive).
  - Canonical encoding ensures byte-for-byte reproducibility across all
    verifiers, even offline and across languages (via JSON spec).
"""
import json


def _assert_canonicalizable(obj) -> None:
    """Reject inputs that would break byte-for-byte cross-language determinism.

    Non-string dict keys are rejected because json coerces them to strings
    ({1: 'a'} and {'1': 'a'} would collide to identical bytes, defeating
    injectivity). Non-finite floats are handled separately by allow_nan=False.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(
                    f"canonical JSON requires string object keys, got {type(k).__name__}"
                )
            _assert_canonicalizable(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _assert_canonicalizable(v)


def canonical_json(obj: dict) -> str:
    """Convert a dict to deterministic JSON string with sorted keys and no whitespace.

    Ensures that the same Python dict always produces identical JSON bytes,
    enabling reproducible hashing. Keys are sorted lexicographically, separators
    are compact (no spaces), and non-ASCII characters (e.g., Japanese text) are
    preserved as-is rather than escaped, improving human readability while
    maintaining byte-for-byte determinism across Python versions and platforms.

    Args:
        obj: A dictionary to serialize (typically a bundle or trace dict).

    Returns:
        A JSON string with sorted keys, no whitespace, and preserved Unicode.

    Examples:
        Input:  {'b': 2, 'a': 1}
        Output: '{"a":1,"b":2}'

        Input:  {'name': '日本', 'count': 3}
        Output: '{"count":3,"name":"日本"}'
    """
    _assert_canonicalizable(obj)
    # allow_nan=False: NaN/Infinity are not valid JSON and are rejected by
    # spec-compliant parsers (Go/JS), so they must never enter a proof bundle.
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def canonical_bytes(obj: dict) -> bytes:
    """Convert a dict to deterministic JSON bytes (UTF-8 encoded).

    Equivalent to canonical_json(obj).encode('utf-8'). Used internally
    to hash dictionaries for bundle integrity checks and trace verification.
    The bytes returned are passed directly to hashlib.sha256(), so encoding
    is critical: UTF-8 is the standard for all hashing in Perathos.

    Args:
        obj: A dictionary to serialize.

    Returns:
        The canonical JSON representation encoded as UTF-8 bytes.

    Examples:
        Input:  {'b': 2, 'a': 1}
        Output: b'{"a":1,"b":2}'

        Input:  {'x': 1}
        Output: b'{"x":1}'
    """
    return canonical_json(obj).encode("utf-8")
