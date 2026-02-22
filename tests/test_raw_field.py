"""Tests for proteus.model.raw_field."""

import json

import pytest

from proteus.model.field_behavior import FieldBehavior
from proteus.model.raw_field import EnhancedJSONEncoder, RawField


class TestEnhancedJSONEncoder:
    """Tests for the custom JSON encoder."""

    def test_encodes_field_behavior_enum(self) -> None:
        """FieldBehavior enum values are serialized as their string value."""
        result = json.dumps(FieldBehavior.FUZZABLE, cls=EnhancedJSONEncoder)
        assert result == '"FUZZABLE"'

    def test_encodes_other_enum(self) -> None:
        """Any Enum member is serialized by its value attribute."""
        from enum import Enum

        class Color(Enum):
            RED = "red"

        result = json.dumps(Color.RED, cls=EnhancedJSONEncoder)
        assert result == '"red"'

    def test_raises_for_non_enum(self) -> None:
        """Non-serialisable non-enum objects raise TypeError."""
        with pytest.raises(TypeError):
            json.dumps(object(), cls=EnhancedJSONEncoder)


class TestRawFieldDefaults:
    """Tests for RawField default values."""

    def test_default_construction(self) -> None:
        rf = RawField()
        assert rf.name == ""
        assert rf.wireshark_name == ""
        assert rf.display_name == ""
        assert rf.pos == 0
        assert rf.relative_pos == 0
        assert rf.size == 0
        assert rf.val == ""
        assert rf.valid_values == []
        assert rf.invalid_values == {}
        assert rf.layer == ""
        assert rf.behavior is FieldBehavior.UNKNOWN
        assert rf.accepted is False

    def test_explicit_construction(self) -> None:
        rf = RawField(
            name="modbus.func_code",
            wireshark_name="modbus.func_code",
            display_name="Function Code",
            pos=7,
            relative_pos=1,
            size=1,
            val="03",
            layer="modbus",
        )
        assert rf.name == "modbus.func_code"
        assert rf.val == "03"
        assert rf.size == 1


class TestRawFieldSetBehavior:
    """Tests for set_behavior."""

    def test_sets_behavior_when_unknown(self) -> None:
        rf = RawField()
        rf.set_behavior(FieldBehavior.FUZZABLE)
        assert rf.behavior is FieldBehavior.FUZZABLE

    def test_does_not_overwrite_non_unknown(self) -> None:
        rf = RawField()
        rf.set_behavior(FieldBehavior.FUZZABLE)
        rf.set_behavior(FieldBehavior.CONSTRAINED)
        assert rf.behavior is FieldBehavior.FUZZABLE  # first write wins

    def test_all_behaviors_can_be_set(self) -> None:
        for behavior in FieldBehavior:
            if behavior is FieldBehavior.UNKNOWN:
                continue
            rf = RawField()
            rf.set_behavior(behavior)
            assert rf.behavior is behavior


class TestRawFieldGetBiggestInvalidCategorySize:
    """Tests for get_biggest_invalid_category_size."""

    def test_returns_zero_when_no_invalid_values(self) -> None:
        rf = RawField()
        assert rf.get_biggest_invalid_category_size() == 0

    def test_returns_max_category_size(self) -> None:
        rf = RawField(
            invalid_values={
                "Timeout": ["aa", "bb", "cc"],
                "Exception": ["11"],
            }
        )
        assert rf.get_biggest_invalid_category_size() == 3  # noqa: PLR2004

    def test_single_category(self) -> None:
        rf = RawField(invalid_values={"err": ["01", "02"]})
        assert rf.get_biggest_invalid_category_size() == 2  # noqa: PLR2004


class TestRawFieldStr:
    """Tests for __str__ representation."""

    def test_str_contains_field_name(self) -> None:
        rf = RawField(name="modbus.func_code", behavior=FieldBehavior.FUZZABLE)
        result = str(rf)
        assert "modbus.func_code" in result

    def test_str_contains_behavior_value(self) -> None:
        rf = RawField(behavior=FieldBehavior.CALCULATED)
        result = str(rf)
        assert "CALCULATED" in result

    def test_str_contains_accepted(self) -> None:
        rf = RawField(accepted=True)
        result = str(rf)
        assert "True" in result

    def test_str_contains_ansi_codes(self) -> None:
        rf = RawField()
        result = str(rf)
        assert "\033[" in result
