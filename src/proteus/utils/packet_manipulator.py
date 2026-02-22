"""Packet manipulation utilities for Proteus."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from proteus.model.raw_field import RawField
    from proteus.protocols.base import ProtocolAdapter


class PacketManipulator:
    """Handles packet construction and mutation operations."""

    @staticmethod
    def construct_prefix(fields: list[RawField], stop_at_name: str) -> bytes:
        """Construct packet bytes from fields up to (but not including) *stop_at_name*."""
        prefix = b""
        for field in fields:
            if field.name == stop_at_name:
                break
            prefix += bytes.fromhex(field.val)
        return prefix

    @staticmethod
    def inject_mutation(
        target_field: RawField,
        base_payload_hex: str,
        mutation_hex: str,
        unique_fields: list[RawField],
        adapter: ProtocolAdapter | None = None,
    ) -> bytearray:
        """Inject *mutation_hex* into *target_field* and recalculate dependent fields via *adapter*."""
        payload_copy = bytearray(bytes.fromhex(base_payload_hex))
        start_index = target_field.relative_pos
        end_index = start_index + target_field.size
        payload_copy[start_index:end_index] = bytes.fromhex(mutation_hex)
        if adapter is not None:
            payload_copy = adapter.update_dependent_fields(payload_copy, base_payload_hex, target_field, unique_fields)
        return payload_copy
