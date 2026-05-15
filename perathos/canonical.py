"""Deterministic canonical JSON encoding for tamper-evident hashing.

Provides a stable JSON representation where key order and formatting are
fixed, enabling reproducible hashes across independent verifiers.
"""
import json


def canonical_json(obj: dict) -> str:
    """Convert a dict to deterministic JSON string with sorted keys and no whitespace.

    Ensures that the same Python dict always produces identical JSON bytes,
    enabling reproducible hashing. Keys are sorted lexicographically, separators
    are compact, and non-ASCII characters (e.g., Japanese text) are preserved
    as-is rather than escaped, improving human readability while maintaining
    byte-for-byte determinism across Python versions and platforms.

    Args:
        obj: A dictionary to serialize (typically a bundle or trace dict).

    Returns:
        A JSON string with sorted keys, no whitespace, and preserved Unicode.
        Example: '{"a":1,"b":2}' for {'b': 2, 'a': 1}.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_bytes(obj: dict) -> bytes:
    """Convert a dict to deterministic JSON bytes (UTF-8 encoded).

    Equivalent to canonical_json(obj).encode('utf-8'). Used internally
    to hash dictionaries for bundle integrity checks and trace verification.

    Args:
        obj: A dictionary to serialize.

    Returns:
        The canonical JSON representation encoded as UTF-8 bytes.
        Example: b'{"a":1,"b":2}' for {'b': 2, 'a': 1}.
    """
    return canonical_json(obj).encode("utf-8")
