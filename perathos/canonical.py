import json


def canonical_json(obj: dict) -> str:
    """Stable JSON: keys sorted, no whitespace, non-ASCII preserved as-is."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_bytes(obj: dict) -> bytes:
    return canonical_json(obj).encode("utf-8")
