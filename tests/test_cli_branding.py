"""Tests for proteus.model.cli_branding."""

import json
from unittest.mock import mock_open, patch

from proteus.model.cli_branding import CliBranding


class TestCliBrandingShowIntro:
    """Tests for CliBranding.show_intro."""

    def test_show_intro_prints_header(self) -> None:
        metadata = json.dumps({"name": "proteus", "title": "ICS Protocol Fuzzer"})
        with patch("builtins.open", mock_open(read_data=metadata)):
            with patch("proteus.model.cli_branding.console") as mock_console:
                CliBranding.show_intro()
                assert mock_console.print.call_count >= 2  # noqa: PLR2004

    def test_show_intro_reads_metadata_json(self) -> None:
        metadata = json.dumps({"name": "test-name", "title": "test-title"})
        with patch("builtins.open", mock_open(read_data=metadata)):
            with patch("proteus.model.cli_branding.console") as mock_console:
                CliBranding.show_intro()
                # Two calls: header print + Panel print
                assert mock_console.print.call_count == 2  # noqa: PLR2004


class TestCliBrandingLogPivot:
    """Tests for CliBranding.log_pivot."""

    def test_log_pivot_prints_offset_and_hex(self) -> None:
        original = bytearray(b"\x01\x02")
        mutated = bytearray(b"\xff\x02")
        with patch("proteus.model.cli_branding.console") as mock_console:
            CliBranding.log_pivot(3, original, mutated)
            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "3" in call_args
            assert "0102" in call_args
            assert "ff02" in call_args

    def test_log_pivot_offset_zero(self) -> None:
        with patch("proteus.model.cli_branding.console") as mock_console:
            CliBranding.log_pivot(0, bytearray(b"\x00"), bytearray(b"\x01"))
            mock_console.print.assert_called_once()
