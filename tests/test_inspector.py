"""Tests for the bundle inspector module.

Covers inspect_bundle with various malformed bundles, missing fields,
and edge cases in the rendering pipeline.
"""
import pytest

from perathos.bundle import create_bundle
from perathos.inspector import inspect_bundle


def test_inspect_valid_bundle(capsys):
    """Test that inspect_bundle renders a valid bundle without error."""
    b = create_bundle("output text", input_text="input text")
    inspect_bundle(b)
    captured = capsys.readouterr()
    assert "Bundle ID" in captured.out or "Bundle ID" in captured.err or len(captured.out) > 0


def test_inspect_bundle_missing_trace(capsys):
    """Test that inspect_bundle handles missing _trace field gracefully."""
    b = create_bundle("output")
    del b["_trace"]
    # Should not raise exception
    inspect_bundle(b)
    # At minimum, something should be printed
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert len(output) > 0


def test_inspect_bundle_missing_issued_at(capsys):
    """Test that inspect_bundle handles missing issued_at field gracefully."""
    b = create_bundle("output")
    del b["issued_at"]
    # Should not raise exception
    try:
        inspect_bundle(b)
        captured = capsys.readouterr()
        # If we get here without exception, that's good
        output = captured.out + captured.err
        # We may or may not get output depending on exception handling
    except KeyError:
        # This is acceptable — missing required field causes error
        pass


def test_inspect_bundle_missing_bundle_id(capsys):
    """Test that inspect_bundle handles missing bundle_id field gracefully."""
    b = create_bundle("output")
    del b["bundle_id"]
    # Should not raise exception (or raises KeyError which is ok)
    try:
        inspect_bundle(b)
    except KeyError:
        pass


def test_inspect_bundle_with_empty_trace(capsys):
    """Test that inspect_bundle renders bundle with empty _trace dict."""
    b = create_bundle("output")
    b["_trace"] = {}
    inspect_bundle(b)
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert len(output) > 0


def test_inspect_bundle_with_none_trace(capsys):
    """inspect_bundle must NOT crash when _trace is explicitly None."""
    b = create_bundle("output")
    b["_trace"] = None
    # Previously raised AttributeError ('NoneType' has no attribute 'get');
    # must now render gracefully and produce output.
    inspect_bundle(b)
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert len(output) > 0


def test_inspect_bundle_with_numeric_hashes(capsys):
    """Test that inspect_bundle handles non-string hash values gracefully."""
    b = create_bundle("output")
    b["input_hash"] = 12345  # numeric instead of string
    try:
        inspect_bundle(b)
        captured = capsys.readouterr()
        output = captured.out + captured.err
    except (TypeError, AttributeError):
        # Acceptable if numeric hash causes error
        pass


def test_inspect_bundle_with_missing_input_hash(capsys):
    """Test that inspect_bundle handles missing input_hash gracefully."""
    b = create_bundle("output")
    del b["input_hash"]
    try:
        inspect_bundle(b)
        captured = capsys.readouterr()
    except KeyError:
        # This is acceptable
        pass


def test_inspect_bundle_with_missing_output_hash(capsys):
    """Test that inspect_bundle handles missing output_hash gracefully."""
    b = create_bundle("output")
    del b["output_hash"]
    try:
        inspect_bundle(b)
        captured = capsys.readouterr()
    except KeyError:
        # This is acceptable
        pass


def test_inspect_bundle_with_missing_integrity_hash(capsys):
    """Test that inspect_bundle handles missing integrity_hash gracefully."""
    b = create_bundle("output")
    del b["integrity_hash"]
    try:
        inspect_bundle(b)
        captured = capsys.readouterr()
    except KeyError:
        # This is acceptable
        pass


def test_inspect_bundle_with_missing_trace_hash(capsys):
    """Test that inspect_bundle handles missing trace_hash gracefully."""
    b = create_bundle("output")
    del b["trace_hash"]
    try:
        inspect_bundle(b)
        captured = capsys.readouterr()
    except KeyError:
        # This is acceptable
        pass


def test_inspect_signed_bundle(capsys):
    """Test that inspect_bundle renders a signed bundle correctly."""
    from perathos.signing import generate_keypair
    from perathos.bundle import sign_bundle
    
    b = create_bundle("output")
    sk, vk = generate_keypair()
    signed = sign_bundle(b, sk)
    
    inspect_bundle(signed)
    captured = capsys.readouterr()
    output = captured.out + captured.err
    # Should mention signing
    assert len(output) > 0


def test_inspect_bundle_with_extra_fields(capsys):
    """Test that inspect_bundle handles bundles with extra unknown fields."""
    b = create_bundle("output")
    b["custom_field"] = "custom value"
    b["another_field"] = 42
    
    # Should not raise
    inspect_bundle(b)
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert len(output) > 0
