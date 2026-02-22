"""Tests for proteus.utils.packet_manipulator."""

import pytest

from proteus.model.raw_field import RawField
from proteus.protocols.modbus import ModbusAdapter
from proteus.utils.packet_manipulator import PacketManipulator


def _make_field(name: str, val: str, relative_pos: int, size: int) -> RawField:
    return RawField(name=name, val=val, relative_pos=relative_pos, size=size)


class TestConstructPrefix:
    """Tests for PacketManipulator.construct_prefix."""

    def test_returns_empty_when_stop_at_first_field(self) -> None:
        fields = [
            _make_field("f1", "0102", 0, 2),
            _make_field("f2", "03", 2, 1),
        ]
        result = PacketManipulator.construct_prefix(fields, stop_at_name="f1")
        assert result == b""

    def test_includes_fields_before_stop(self) -> None:
        fields = [
            _make_field("f1", "0102", 0, 2),
            _make_field("f2", "03", 2, 1),
            _make_field("f3", "04", 3, 1),
        ]
        result = PacketManipulator.construct_prefix(fields, stop_at_name="f3")
        assert result == bytes.fromhex("010203")

    def test_returns_all_when_stop_name_absent(self) -> None:
        fields = [
            _make_field("f1", "aa", 0, 1),
            _make_field("f2", "bb", 1, 1),
        ]
        result = PacketManipulator.construct_prefix(fields, stop_at_name="nonexistent")
        assert result == bytes.fromhex("aabb")

    def test_returns_empty_for_empty_fields(self) -> None:
        result = PacketManipulator.construct_prefix([], stop_at_name="f1")
        assert result == b""


class TestInjectMutation:
    """Tests for PacketManipulator.inject_mutation."""

    def test_replaces_single_byte(self) -> None:
        base = "0102030405"
        target = _make_field("f", "02", 1, 1)
        result = PacketManipulator.inject_mutation(target, base, "ff", unique_fields=[target])
        assert result[1] == 0xFF

    def test_replaces_multi_byte(self) -> None:
        base = "0102030405"
        target = _make_field("f", "0203", 1, 2)
        result = PacketManipulator.inject_mutation(target, base, "aabb", unique_fields=[target])
        assert result[1:3] == bytes.fromhex("aabb")

    def test_does_not_modify_other_bytes_without_adapter(self) -> None:
        base = "0102030405"
        target = _make_field("f", "03", 2, 1)
        result = PacketManipulator.inject_mutation(target, base, "cc", unique_fields=[target])
        assert result[0] == 0x01
        assert result[1] == 0x02
        assert result[2] == 0xCC
        assert result[3] == 0x04
        assert result[4] == 0x05

    def test_calls_adapter_update(self) -> None:
        """Adapter.update_dependent_fields is invoked when adapter is provided."""
        # Build a minimal Modbus-like packet: 12 bytes total
        # MBAP header (6 bytes) + unit id (1) + func_code (1) + data (4)
        # For this test we just check the adapter path runs without error.
        base = "000100000006" + "01" + "03" + "00000002"
        # len field (bytes 4-5 of MBAP, relative_pos=4, size=2, name="mbtcp.len")
        len_field = RawField(name="mbtcp.len", relative_pos=4, size=2, val="0006")
        func_field = RawField(name="modbus.func_code", relative_pos=7, size=1, val="03")
        adapter = ModbusAdapter()
        result = PacketManipulator.inject_mutation(
            func_field, base, "04", unique_fields=[len_field, func_field], adapter=adapter
        )
        assert isinstance(result, bytearray)
        assert result[7] == 0x04
