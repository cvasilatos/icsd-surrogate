"""Modbus TCP protocol adapter."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, ClassVar

from proteus.protocols.base import ProtocolAdapter
from proteus.utils.packet_manipulator import inject_mutation

if TYPE_CHECKING:
    from proteus.model.raw_field import RawField


class ModbusAdapter(ProtocolAdapter):
    """Protocol adapter for Modbus TCP (mbtcp)."""

    _MBAP_HEADER_SIZE: int = 6
    _FUNCTION_CODES: ClassVar[list[str]] = ["01", "02", "03", "04", "05", "06"]
    _PAYLOAD_LENGTHS: ClassVar[list[int]] = [0, 2, 4, 8, 16]

    @property
    def pivot_field_name(self) -> str:
        """Return the Modbus function-code field name used as structural pivot."""
        return "modbus.func_code"

    @property
    def structural_function_codes(self) -> list[str]:
        """Return standard Modbus function codes for structural variant generation."""
        return self._FUNCTION_CODES

    @property
    def structural_payload_lengths(self) -> list[int]:
        """Return payload lengths used when generating Modbus structural variants."""
        return self._PAYLOAD_LENGTHS

    def fix_length_field(self, packet_bytes: bytes, len_field: RawField) -> bytes:
        """Rewrite *len_field* to reflect the actual Modbus TCP PDU length."""
        length_value = len(packet_bytes) - self._MBAP_HEADER_SIZE
        length_bytes = struct.pack(">H", length_value)
        start_pos = len_field.relative_pos + 1
        end_pos = start_pos + len_field.size + 1
        return packet_bytes[:start_pos] + b"\x00" + length_bytes + packet_bytes[end_pos:]

    def update_dependent_fields(self, payload: bytearray, base_payload_hex: str, target_field: RawField, unique_fields: list[RawField]) -> bytearray:
        """Recalculate Modbus length fields after a mutation has been injected."""
        for field in unique_fields:
            if ".len" in field.name.lower() and target_field.name != field.name:
                total_bytes = len(base_payload_hex) // 2
                payload_len = total_bytes - self._MBAP_HEADER_SIZE
                start = field.relative_pos
                end = start + field.size
                payload = payload[:start] + payload_len.to_bytes(field.size, byteorder="big") + payload[end:]
        return payload

    def get_additional_mutations(self, fields: list[RawField], seed: str) -> list[str]:
        """Return 100 copies of the packet with function code set to 0xff for stress testing."""
        mutations: list[str] = []
        for field in fields:
            if field.name == self.pivot_field_name:
                mutations.extend(inject_mutation(field, seed, "ff", unique_fields=fields, adapter=self).hex() for _ in range(100))
        return mutations
