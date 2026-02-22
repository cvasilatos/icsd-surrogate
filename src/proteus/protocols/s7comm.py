"""S7Comm protocol adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from proteus.protocols.base import ProtocolAdapter

if TYPE_CHECKING:
    from proteus.model.raw_field import RawField


class S7CommAdapter(ProtocolAdapter):
    """Protocol adapter for S7Comm (ISO on TCP)."""

    _FUNCTION_CODES: ClassVar[list[str]] = ["04", "05"]
    _PAYLOAD_LENGTHS: ClassVar[list[int]] = [0, 2, 4, 8]

    @property
    def pivot_field_name(self) -> str:
        """Return the S7Comm function-code field name used as structural pivot."""
        return "s7comm.param.func"

    @property
    def structural_function_codes(self) -> list[str]:
        """Return S7Comm function codes for structural variant generation."""
        return self._FUNCTION_CODES

    @property
    def structural_payload_lengths(self) -> list[int]:
        """Return payload lengths used when generating S7Comm structural variants."""
        return self._PAYLOAD_LENGTHS

    def fix_length_field(self, packet_bytes: bytes, len_field: RawField) -> bytes:
        """Rewrite *len_field* to reflect the total S7Comm packet length (no header subtraction, unlike Modbus/DNP3)."""
        length_value = len(packet_bytes)
        start = len_field.relative_pos
        end = start + len_field.size
        return packet_bytes[:start] + length_value.to_bytes(len_field.size, byteorder="big") + packet_bytes[end:]

    def update_dependent_fields(
        self,
        payload: bytearray,
        base_payload_hex: str,
        target_field: RawField,
        unique_fields: list[RawField],
    ) -> bytearray:
        """Recalculate S7Comm length fields after a mutation has been injected.

        Length fields are set to the total byte count of the *base* (pre-mutation) packet,
        consistent with the assumption that mutations do not change the packet size.
        """
        for field in unique_fields:
            if ".len" in field.name.lower() and target_field.name != field.name:
                total_bytes = len(base_payload_hex) // 2
                start = field.relative_pos
                end = start + field.size
                payload = payload[:start] + total_bytes.to_bytes(field.size, byteorder="big") + payload[end:]
        return payload

    def get_additional_mutations(self, fields: list[RawField], seed: str) -> list[str]:  # noqa: ARG002
        """Return an empty list — S7Comm requires no extra mutation rounds."""
        return []
