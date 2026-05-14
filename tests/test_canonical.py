from perathos.canonical import canonical_bytes, canonical_json


def test_sorted_keys():
    result = canonical_json({"b": 2, "a": 1})
    assert result == '{"a":1,"b":2}'


def test_no_whitespace():
    result = canonical_json({"k": "v"})
    assert " " not in result


def test_non_ascii_preserved():
    result = canonical_json({"k": "日本語"})
    assert "日本語" in result


def test_canonical_bytes_is_utf8():
    b = canonical_bytes({"x": 1})
    assert isinstance(b, bytes)
    assert b == b'{"x":1}'


def test_deterministic():
    obj = {"z": 3, "a": 1, "m": 2}
    assert canonical_json(obj) == canonical_json(obj)
    assert canonical_json(obj) == canonical_json({"a": 1, "m": 2, "z": 3})
