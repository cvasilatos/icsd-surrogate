"""DNP3 protocol adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from proteus.protocols.base import ProtocolAdapter

if TYPE_CHECKING:
    from proteus.model.raw_field import RawField


class Dnp3Adapter(ProtocolAdapter):
    """Protocol adapter for DNP3."""

    _DATA_LINK_HEADER_SIZE: int = 2
    _FUNCTION_CODES: ClassVar[list[str]] = ["01", "02", "03", "81"]
    _PAYLOAD_LENGTHS: ClassVar[list[int]] = [0, 2, 4, 8]
    _CRC_POLYNOMIAL: int = 0xA6BC

    @property
    def pivot_field_name(self) -> str:
        """Return the DNP3 function-code field name used as structural pivot."""
        return "dnp3.ctl.func"

    @property
    def structural_function_codes(self) -> list[str]:
        """Return DNP3 function codes for structural variant generation."""
        return self._FUNCTION_CODES

    @property
    def structural_payload_lengths(self) -> list[int]:
        """Return payload lengths used when generating DNP3 structural variants."""
        return self._PAYLOAD_LENGTHS

    def fix_length_field(self, packet_bytes: bytes, len_field: RawField) -> bytes:
        """Rewrite *len_field* to reflect the actual DNP3 data-link frame length."""
        length_value = len(packet_bytes) - self._DATA_LINK_HEADER_SIZE
        start = len_field.relative_pos
        end = start + len_field.size
        return packet_bytes[:start] + length_value.to_bytes(len_field.size, byteorder="little") + packet_bytes[end:]

    def update_dependent_fields(
        self,
        payload: bytearray,
        base_payload_hex: str,
        target_field: RawField,
        unique_fields: list[RawField],
    ) -> bytearray:
        """Recalculate DNP3 length and CRC fields after a mutation has been injected."""
        prev = 0
        for field in unique_fields:
            if ".len" in field.name.lower() and target_field.name != field.name:
                total_bytes = len(base_payload_hex) // 2
                payload_len = total_bytes - self._DATA_LINK_HEADER_SIZE
                start = field.relative_pos
                end = start + field.size
                payload = payload[:start] + payload_len.to_bytes(field.size, byteorder="little") + payload[end:]
            elif "crc" in field.name.lower() and target_field.name != field.name:
                start = field.relative_pos
                end = start + field.size
                crc_value = self._calculate_crc(payload[prev:start])
                prev = end
                payload = payload[:start] + crc_value.to_bytes(field.size, byteorder="little") + payload[end:]
        return payload

    def _calculate_crc(self, data: bytearray) -> int:
        """Calculate a DNP3 CRC-16 checksum for *data* using the DNP3 polynomial ``0xA6BC``."""
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ self._CRC_POLYNOMIAL
                else:
                    crc >>= 1
        return (~crc) & 0xFFFF

    def get_additional_mutations(self, fields: list[RawField], seed: str) -> list[str]:  # noqa: ARG002
        """Return an empty list — DNP3 requires no extra mutation rounds."""
        return []
