"""Tests for proteus.utils.response_validator."""

from proteus.utils.response_validator import is_valid_response


class TestIsValidResponse:
    """Tests for the is_valid_response helper."""

    def test_empty_response_is_invalid(self) -> None:
        assert is_valid_response(b"") is False

    def test_all_zero_prefix_is_invalid(self) -> None:
        """Responses that start with '0000' (hex) are considered invalid."""
        assert is_valid_response(bytes.fromhex("0000aabbcc")) is False

    def test_short_error_code_suffix_is_invalid(self) -> None:
        """A 2-byte response ending with '04' is treated as a bare error code."""
        assert is_valid_response(bytes.fromhex("0104")) is False

    def test_valid_short_response(self) -> None:
        """Responses that don't match any invalid pattern are valid."""
        assert is_valid_response(bytes.fromhex("0103020000")) is True

    def test_valid_longer_response(self) -> None:
        assert is_valid_response(bytes.fromhex("0103060001000200030000")) is True

    def test_response_ending_with_error_code_but_longer_is_valid(self) -> None:
        """A long response ending with '04' should still be valid (length > 4)."""
        assert is_valid_response(bytes.fromhex("010304aabb04")) is True

    def test_non_zero_prefix_is_valid(self) -> None:
        assert is_valid_response(bytes.fromhex("01020304")) is True
