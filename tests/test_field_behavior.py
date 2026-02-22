"""Tests for proteus.model.field_behavior."""

from proteus.model.field_behavior import FieldBehavior


class TestFieldBehavior:
    """Tests for the FieldBehavior enum."""

    def test_all_values_exist(self) -> None:
        """Verify all expected enum members are defined."""
        assert FieldBehavior.UNKNOWN.value == "UNKNOWN"
        assert FieldBehavior.FUZZABLE.value == "FUZZABLE"
        assert FieldBehavior.CONSTRAINED.value == "CONSTRAINED"
        assert FieldBehavior.CALCULATED.value == "CALCULATED"
        assert FieldBehavior.WIRESHARK.value == "WIRESHARK"
        assert FieldBehavior.SERVER_ERROR.value == "SERVER_ERROR"

    def test_color_unknown(self) -> None:
        """UNKNOWN behavior returns the default black color."""
        assert FieldBehavior.UNKNOWN.color == "black"

    def test_color_fuzzable(self) -> None:
        assert FieldBehavior.FUZZABLE.color == "green"

    def test_color_constrained(self) -> None:
        assert FieldBehavior.CONSTRAINED.color == "yellow"

    def test_color_calculated(self) -> None:
        assert FieldBehavior.CALCULATED.color == "blue"

    def test_color_wireshark(self) -> None:
        assert FieldBehavior.WIRESHARK.color == "red"

    def test_color_server_error(self) -> None:
        assert FieldBehavior.SERVER_ERROR.color == "magenta"

    def test_enum_from_value(self) -> None:
        """Ensure enum members can be retrieved by value."""
        assert FieldBehavior("FUZZABLE") is FieldBehavior.FUZZABLE

    def test_enum_iteration(self) -> None:
        """All six members are present when iterating."""
        members = list(FieldBehavior)
        assert len(members) == 6  # noqa: PLR2004
