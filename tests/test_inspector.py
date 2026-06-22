"""Tests for the bundle inspector.

inspect_bundle is a display tool that may be handed a hand-edited or foreign
bundle, so its contract is: render best-effort and NEVER crash on a dict input.
These tests assert that contract (no try/except-pass escape hatches).
"""
from perathos.bundle import create_bundle, sign_bundle
from perathos.inspector import inspect_bundle
from perathos.signing import generate_keypair


def _out(capsys) -> str:
    c = capsys.readouterr()
    return c.out + c.err


def test_inspect_valid_bundle(capsys):
    inspect_bundle(create_bundle("output text", input_text="input text"))
    assert "Bundle ID" in _out(capsys)


def test_inspect_missing_trace(capsys):
    b = create_bundle("output")
    del b["_trace"]
    inspect_bundle(b)
    assert len(_out(capsys)) > 0


def test_inspect_none_trace(capsys):
    b = create_bundle("output")
    b["_trace"] = None
    inspect_bundle(b)
    assert len(_out(capsys)) > 0


def test_inspect_empty_trace(capsys):
    b = create_bundle("output")
    b["_trace"] = {}
    inspect_bundle(b)
    assert len(_out(capsys)) > 0


def test_inspect_missing_issued_at(capsys):
    b = create_bundle("output")
    del b["issued_at"]
    inspect_bundle(b)
    assert len(_out(capsys)) > 0


def test_inspect_missing_bundle_id(capsys):
    b = create_bundle("output")
    del b["bundle_id"]
    inspect_bundle(b)
    assert len(_out(capsys)) > 0


def test_inspect_numeric_hashes(capsys):
    b = create_bundle("output")
    b["input_hash"] = 12345
    inspect_bundle(b)
    assert len(_out(capsys)) > 0


def test_inspect_missing_hash_fields(capsys):
    for field in ("input_hash", "output_hash", "integrity_hash", "trace_hash"):
        b = create_bundle("output")
        del b[field]
        inspect_bundle(b)
        assert len(_out(capsys)) > 0


def test_inspect_signed_bundle(capsys):
    b = create_bundle("output")
    sk, _ = generate_keypair()
    inspect_bundle(sign_bundle(b, sk))
    assert "SIGNED" in _out(capsys)


def test_inspect_extra_fields(capsys):
    b = create_bundle("output")
    b["custom_field"] = "custom value"
    b["another_field"] = 42
    inspect_bundle(b)
    assert len(_out(capsys)) > 0
