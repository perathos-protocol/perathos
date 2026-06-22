"""Tests for CLI helper functions and command behavior."""
from perathos.cli import _format_hash, _explain_error


class TestFormatHash:
    """Tests for the _format_hash() helper function."""

    def test_format_hash_verbose_returns_full_hash(self):
        """In verbose mode, _format_hash should return the full hash unchanged."""
        full_hash = "a665a45920422f9d417e4867efdc4fb8a067e80b0456b3a9c52c1e4e81e2f4de"
        result = _format_hash(full_hash, verbose=True)
        assert result == full_hash
        assert len(result) == 64

    def test_format_hash_normal_truncates_to_8_chars(self):
        """In normal mode, _format_hash should truncate to 8 chars + '...'."""
        full_hash = "a665a45920422f9d417e4867efdc4fb8a067e80b0456b3a9c52c1e4e81e2f4de"
        result = _format_hash(full_hash, verbose=False)
        assert result == "a665a459..."
        assert len(result) == 11  # 8 chars + "..."

    def test_format_hash_empty_string(self):
        """_format_hash should handle empty strings gracefully."""
        result = _format_hash("", verbose=False)
        assert result == "..."
        result_verbose = _format_hash("", verbose=True)
        assert result_verbose == ""

    def test_format_hash_short_hash_less_than_8_chars(self):
        """_format_hash should handle hashes shorter than 8 characters."""
        short_hash = "a1b2c3d4"  # exactly 8 chars
        result = _format_hash(short_hash, verbose=False)
        assert result == "a1b2c3d4..."
        assert result[:8] == short_hash

    def test_format_hash_shorter_than_8_chars(self):
        """_format_hash should handle hashes shorter than 8 characters gracefully."""
        short_hash = "abc"  # 3 chars
        result = _format_hash(short_hash, verbose=False)
        assert result == "abc..."
        assert len(result) == 6  # 3 chars + "..."

    def test_format_hash_single_char(self):
        """_format_hash should handle single-character hashes."""
        single_char = "a"
        result = _format_hash(single_char, verbose=False)
        assert result == "a..."

    def test_format_hash_exactly_8_chars(self):
        """_format_hash with exactly 8 characters should show all 8 + '...'."""
        hash_8_chars = "12345678"
        result = _format_hash(hash_8_chars, verbose=False)
        assert result == "12345678..."
        assert len(result) == 11

    def test_format_hash_9_chars(self):
        """_format_hash with 9 characters should truncate to first 8 + '...'."""
        hash_9_chars = "123456789"
        result = _format_hash(hash_9_chars, verbose=False)
        assert result == "12345678..."
        assert len(result) == 11

    def test_format_hash_uuid_like_string(self):
        """_format_hash should truncate UUID-like strings correctly."""
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        result = _format_hash(uuid_str, verbose=False)
        assert result == "550e8400..."
        result_verbose = _format_hash(uuid_str, verbose=True)
        assert result_verbose == uuid_str

    def test_format_hash_verbose_flag_true(self):
        """_format_hash with verbose=True should always return full hash."""
        hashes = [
            "a" * 64,  # SHA-256 length
            "b" * 32,
            "c" * 128,
            "d",
            "",
        ]
        for h in hashes:
            result = _format_hash(h, verbose=True)
            assert result == h, f"verbose=True should return full hash, got {result}"

    def test_format_hash_verbose_flag_false(self):
        """_format_hash with verbose=False should truncate all hashes consistently."""
        hashes = [
            "a" * 64,  # SHA-256 length
            "b" * 100,
            "c" * 16,
        ]
        for h in hashes:
            result = _format_hash(h, verbose=False)
            expected = f"{h[:8]}..."
            assert result == expected, f"Expected {expected}, got {result}"


class TestExplainError:
    """Tests for the _explain_error() helper function."""

    def test_explain_error_missing_trace(self):
        """_explain_error should map ERR_MISSING_TRACE to explanation."""
        result = _explain_error("ERR_MISSING_TRACE")
        assert "execution metadata" in result.lower()
        assert "corrupted" in result.lower()

    def test_explain_error_trace_hash_mismatch(self):
        """_explain_error should map ERR_TRACE_HASH_MISMATCH to explanation."""
        result = _explain_error("ERR_TRACE_HASH_MISMATCH")
        assert "tampered" in result.lower()

    def test_explain_error_integrity_hash_mismatch(self):
        """_explain_error should map ERR_INTEGRITY_HASH_MISMATCH to explanation."""
        result = _explain_error("ERR_INTEGRITY_HASH_MISMATCH")
        assert "fields" in result.lower() or "modified" in result.lower()

    def test_explain_error_bundle_id_mismatch(self):
        """_explain_error should map ERR_BUNDLE_ID_MISMATCH to explanation."""
        result = _explain_error("ERR_BUNDLE_ID_MISMATCH")
        assert "bundle_id" in result.lower()

    def test_explain_error_bad_signature(self):
        """_explain_error should map ERR_BAD_SIGNATURE to explanation."""
        result = _explain_error("ERR_BAD_SIGNATURE")
        assert "signature" in result.lower()

    def test_explain_error_unknown_code(self):
        """_explain_error should return the original code for unknown errors."""
        unknown = "ERR_UNKNOWN_ERROR_CODE"
        result = _explain_error(unknown)
        assert result == unknown

    def test_explain_error_with_suffix(self):
        """_explain_error should extract base code from error with suffix."""
        # Error codes can have suffixes like "ERR_MISSING_FIELD:output_hash"
        result = _explain_error("ERR_MISSING_TRACE:some_detail")
        # Should match the base code
        expected = _explain_error("ERR_MISSING_TRACE")
        assert result == expected

    def test_explain_error_colon_separated_suffix(self):
        """_explain_error should handle colon-separated error codes."""
        # Tests that the split on ":" works correctly
        result_with_suffix = _explain_error("ERR_TRACE_HASH_MISMATCH:extra_info")
        result_without_suffix = _explain_error("ERR_TRACE_HASH_MISMATCH")
        assert result_with_suffix == result_without_suffix
