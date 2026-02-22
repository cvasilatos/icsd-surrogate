"""Tests for protocol adapters: Modbus, DNP3, S7Comm."""

import struct

from proteus.model.raw_field import RawField
from proteus.protocols.dnp3 import Dnp3Adapter
from proteus.protocols.modbus import ModbusAdapter
from proteus.protocols.s7comm import S7CommAdapter


def _make_field(name: str, relative_pos: int, size: int, val: str = "00") -> RawField:
    return RawField(name=name, relative_pos=relative_pos, size=size, val=val)


# ---------------------------------------------------------------------------
# ModbusAdapter
# ---------------------------------------------------------------------------


class TestModbusAdapterProperties:
    """Tests for ModbusAdapter property accessors."""

    def setup_method(self) -> None:
        self.adapter = ModbusAdapter()

    def test_pivot_field_name(self) -> None:
        assert self.adapter.pivot_field_name == "modbus.func_code"

    def test_structural_function_codes(self) -> None:
        codes = self.adapter.structural_function_codes
        assert isinstance(codes, list)
        assert "01" in codes
        assert "06" in codes

    def test_structural_payload_lengths(self) -> None:
        lengths = self.adapter.structural_payload_lengths
        assert isinstance(lengths, list)
        assert 0 in lengths


class TestModbusFixLengthField:
    """Tests for ModbusAdapter.fix_length_field."""

    def setup_method(self) -> None:
        self.adapter = ModbusAdapter()

    def test_length_value_reflects_pdu_length(self) -> None:
        # 6-byte MBAP header + 6 bytes PDU = 12 total
        packet = bytes(12)
        # len field lives at relative_pos=4 (bytes 5-6 in MBAP, 0-indexed)
        len_field = _make_field("mbtcp.len", relative_pos=4, size=2)
        result = self.adapter.fix_length_field(packet, len_field)
        # PDU length = 12 - 6 = 6
        # start_pos = relative_pos + 1 = 5
        # bytes at [5] should be 0x00 and [6:8] should be struct.pack(">H", 6)
        assert result[5] == 0x00
        pdu_len = struct.unpack(">H", result[6:8])[0]
        assert pdu_len == 6  # noqa: PLR2004

    def test_packet_length_preserved(self) -> None:
        packet = b"\xab\xcd" * 6  # 12 bytes
        len_field = _make_field("mbtcp.len", relative_pos=4, size=2)
        result = self.adapter.fix_length_field(packet, len_field)
        assert len(result) == len(packet)


class TestModbusUpdateDependentFields:
    """Tests for ModbusAdapter.update_dependent_fields."""

    def setup_method(self) -> None:
        self.adapter = ModbusAdapter()

    def test_updates_length_field(self) -> None:
        # 12-byte base packet hex
        base_hex = "0001000000060110001000020000"  # 14 bytes
        payload = bytearray(bytes.fromhex(base_hex))
        len_field = _make_field("mbtcp.len", relative_pos=4, size=2)
        func_field = _make_field("modbus.func_code", relative_pos=7, size=1)
        result = self.adapter.update_dependent_fields(
            payload, base_hex, func_field, [len_field, func_field]
        )
        # expected PDU length = 14 - 6 = 8
        updated_len = int.from_bytes(result[4:6], byteorder="big")
        assert updated_len == 8  # noqa: PLR2004

    def test_skips_length_field_when_target(self) -> None:
        base_hex = "000100000006011000100002"  # 12 bytes
        payload = bytearray(bytes.fromhex(base_hex))
        len_field = _make_field("mbtcp.len", relative_pos=4, size=2)
        # target IS the len field — should NOT update it
        original_bytes = bytes(payload[4:6])
        result = self.adapter.update_dependent_fields(
            payload, base_hex, len_field, [len_field]
        )
        assert result[4:6] == bytearray(original_bytes)

    def test_ignores_non_length_fields(self) -> None:
        base_hex = "000100000006011000100002"  # 12 bytes
        payload = bytearray(bytes.fromhex(base_hex))
        other_field = _make_field("modbus.func_code", relative_pos=7, size=1)
        original = bytearray(payload)
        result = self.adapter.update_dependent_fields(
            payload, base_hex, other_field, [other_field]
        )
        assert result == original


class TestModbusGetAdditionalMutations:
    """Tests for ModbusAdapter.get_additional_mutations."""

    def setup_method(self) -> None:
        self.adapter = ModbusAdapter()

    def test_returns_100_mutations_for_func_code_field(self) -> None:
        # minimal valid-looking packet: 12 bytes
        seed = "000100000006" + "01" + "03" + "00000002"
        func_field = RawField(name="modbus.func_code", relative_pos=7, size=1, val="03")
        len_field = RawField(name="mbtcp.len", relative_pos=4, size=2, val="0006")
        mutations = self.adapter.get_additional_mutations([len_field, func_field], seed)
        assert len(mutations) == 100  # noqa: PLR2004

    def test_returns_empty_when_no_func_code_field(self) -> None:
        seed = "000100000006" + "01" + "03" + "00000002"
        other_field = RawField(
            name="modbus.data", relative_pos=8, size=4, val="00000002"
        )
        mutations = self.adapter.get_additional_mutations([other_field], seed)
        assert mutations == []


# ---------------------------------------------------------------------------
# Dnp3Adapter
# ---------------------------------------------------------------------------


class TestDnp3AdapterProperties:
    """Tests for Dnp3Adapter property accessors."""

    def setup_method(self) -> None:
        self.adapter = Dnp3Adapter()

    def test_pivot_field_name(self) -> None:
        assert self.adapter.pivot_field_name == "dnp3.ctl.func"

    def test_structural_function_codes(self) -> None:
        codes = self.adapter.structural_function_codes
        assert "01" in codes
        assert "81" in codes

    def test_structural_payload_lengths(self) -> None:
        lengths = self.adapter.structural_payload_lengths
        assert 0 in lengths


class TestDnp3FixLengthField:
    """Tests for Dnp3Adapter.fix_length_field."""

    def setup_method(self) -> None:
        self.adapter = Dnp3Adapter()

    def test_length_value_reflects_frame_minus_data_link_header(self) -> None:
        # 10 total bytes, DATA_LINK_HEADER_SIZE=2 → length = 8
        packet = bytes(10)
        len_field = _make_field("dnp3.len", relative_pos=0, size=1)
        result = self.adapter.fix_length_field(packet, len_field)
        # little-endian, 1 byte
        assert result[0] == 8  # noqa: PLR2004

    def test_packet_length_preserved(self) -> None:
        packet = bytes(10)
        len_field = _make_field("dnp3.len", relative_pos=0, size=2)
        result = self.adapter.fix_length_field(packet, len_field)
        assert len(result) == len(packet)


class TestDnp3UpdateDependentFields:
    """Tests for Dnp3Adapter.update_dependent_fields."""

    def setup_method(self) -> None:
        self.adapter = Dnp3Adapter()

    def test_updates_length_field(self) -> None:
        base_hex = "0506" + "c0c1" + "01" + "00"  # 6 bytes
        payload = bytearray(bytes.fromhex(base_hex))
        len_field = _make_field("dnp3.len", relative_pos=0, size=1)
        func_field = _make_field("dnp3.ctl.func", relative_pos=4, size=1)
        result = self.adapter.update_dependent_fields(
            payload, base_hex, func_field, [len_field, func_field]
        )
        # expected: 6 - 2 = 4
        assert result[0] == 4  # noqa: PLR2004

    def test_updates_crc_field(self) -> None:
        base_hex = "0001020304050607"  # 8 bytes
        payload = bytearray(bytes.fromhex(base_hex))
        crc_field = _make_field("dnp3.crc", relative_pos=6, size=2)
        func_field = _make_field("dnp3.ctl.func", relative_pos=2, size=1)
        # Should not raise
        result = self.adapter.update_dependent_fields(
            payload, base_hex, func_field, [crc_field, func_field]
        )
        assert isinstance(result, bytearray)

    def test_skips_length_field_when_target(self) -> None:
        base_hex = "0506c0c10100"
        payload = bytearray(bytes.fromhex(base_hex))
        len_field = _make_field("dnp3.len", relative_pos=0, size=1)
        original_byte = payload[0]
        result = self.adapter.update_dependent_fields(
            payload, base_hex, len_field, [len_field]
        )
        assert result[0] == original_byte

    def test_skips_crc_field_when_target(self) -> None:
        base_hex = "0001020304050607"
        payload = bytearray(bytes.fromhex(base_hex))
        crc_field = _make_field("dnp3.crc", relative_pos=6, size=2)
        original = bytearray(payload)
        result = self.adapter.update_dependent_fields(
            payload, base_hex, crc_field, [crc_field]
        )
        assert result == original

    def test_get_additional_mutations_returns_empty(self) -> None:
        adapter = Dnp3Adapter()
        result = adapter.get_additional_mutations([], "deadbeef")
        assert result == []


class TestDnp3CalculateCrc:
    """Tests for Dnp3Adapter._calculate_crc."""

    def setup_method(self) -> None:
        self.adapter = Dnp3Adapter()

    def test_returns_int(self) -> None:
        crc = self.adapter._calculate_crc(bytearray(b"\x00\x01\x02"))
        assert isinstance(crc, int)

    def test_empty_data(self) -> None:
        # Should not raise and should return a valid 16-bit value
        crc = self.adapter._calculate_crc(bytearray())
        assert 0 <= crc <= 0xFFFF

    def test_deterministic(self) -> None:
        data = bytearray(b"\xde\xad\xbe\xef")
        assert self.adapter._calculate_crc(data) == self.adapter._calculate_crc(data)

    def test_different_data_produces_different_crc(self) -> None:
        crc1 = self.adapter._calculate_crc(bytearray(b"\x00"))
        crc2 = self.adapter._calculate_crc(bytearray(b"\xff"))
        assert crc1 != crc2


# ---------------------------------------------------------------------------
# S7CommAdapter
# ---------------------------------------------------------------------------


class TestS7CommAdapterProperties:
    """Tests for S7CommAdapter property accessors."""

    def setup_method(self) -> None:
        self.adapter = S7CommAdapter()

    def test_pivot_field_name(self) -> None:
        assert self.adapter.pivot_field_name == "s7comm.param.func"

    def test_structural_function_codes(self) -> None:
        codes = self.adapter.structural_function_codes
        assert "04" in codes
        assert "05" in codes

    def test_structural_payload_lengths(self) -> None:
        lengths = self.adapter.structural_payload_lengths
        assert 0 in lengths


class TestS7CommFixLengthField:
    """Tests for S7CommAdapter.fix_length_field."""

    def setup_method(self) -> None:
        self.adapter = S7CommAdapter()

    def test_length_value_equals_total_packet_length(self) -> None:
        packet = bytes(10)
        len_field = _make_field("s7comm.header.dlen", relative_pos=2, size=2)
        result = self.adapter.fix_length_field(packet, len_field)
        updated_len = int.from_bytes(result[2:4], byteorder="big")
        assert updated_len == 10  # noqa: PLR2004

    def test_packet_length_preserved(self) -> None:
        packet = bytes(8)
        len_field = _make_field("s7comm.header.dlen", relative_pos=2, size=2)
        result = self.adapter.fix_length_field(packet, len_field)
        assert len(result) == len(packet)


class TestS7CommUpdateDependentFields:
    """Tests for S7CommAdapter.update_dependent_fields."""

    def setup_method(self) -> None:
        self.adapter = S7CommAdapter()

    def test_updates_length_field(self) -> None:
        base_hex = "0300001104e30000000700f0000001000103c0"  # 19 bytes
        payload = bytearray(bytes.fromhex(base_hex))
        len_field = _make_field("s7comm.header.len", relative_pos=2, size=2)
        func_field = _make_field("s7comm.param.func", relative_pos=14, size=1)
        result = self.adapter.update_dependent_fields(
            payload, base_hex, func_field, [len_field, func_field]
        )
        updated_len = int.from_bytes(result[2:4], byteorder="big")
        assert updated_len == 19  # noqa: PLR2004

    def test_skips_target_field(self) -> None:
        base_hex = "0300001104e3"
        payload = bytearray(bytes.fromhex(base_hex))
        len_field = _make_field("s7comm.header.dlen", relative_pos=2, size=2)
        original = bytearray(payload)
        result = self.adapter.update_dependent_fields(
            payload, base_hex, len_field, [len_field]
        )
        assert result == original

    def test_ignores_non_length_fields(self) -> None:
        base_hex = "0300001104e3"
        payload = bytearray(bytes.fromhex(base_hex))
        other_field = _make_field("s7comm.param.func", relative_pos=5, size=1)
        original = bytearray(payload)
        result = self.adapter.update_dependent_fields(
            payload, base_hex, other_field, [other_field]
        )
        assert result == original

    def test_get_additional_mutations_returns_empty(self) -> None:
        adapter = S7CommAdapter()
        result = adapter.get_additional_mutations([], "deadbeef")
        assert result == []
