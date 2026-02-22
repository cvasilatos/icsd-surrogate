"""Abstract base class for protocol adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from proteus.model.raw_field import RawField


class ProtocolAdapter(ABC):
    """Defines the contract that every protocol implementation must fulfil.

    Each concrete adapter encapsulates all protocol-specific knowledge so that
    the rest of the fuzzer remains protocol-agnostic.
    """

    @property
    @abstractmethod
    def pivot_field_name(self) -> str:
        """Fully-qualified Wireshark field name used as the structural analysis pivot (e.g. ``'modbus.func_code'``)."""

    @property
    @abstractmethod
    def structural_function_codes(self) -> list[str]:
        """Lowercase hex-encoded function codes (without ``0x`` prefix, e.g. ``['01', '02']``) used when generating structural variants."""

    @property
    @abstractmethod
    def structural_payload_lengths(self) -> list[int]:
        """Payload byte lengths used when generating structural variants."""

    @abstractmethod
    def fix_length_field(self, packet_bytes: bytes, len_field: RawField) -> bytes:
        """Rewrite *len_field* inside *packet_bytes* to reflect the current packet length."""

    @abstractmethod
    def update_dependent_fields(
        self,
        payload: bytearray,
        base_payload_hex: str,
        target_field: RawField,
        unique_fields: list[RawField],
    ) -> bytearray:
        """Recalculate length and checksum fields after a mutation has been injected."""

    @abstractmethod
    def get_additional_mutations(self, fields: list[RawField], seed: str) -> list[str]:
        """Return a list of hex-encoded packets for protocol-specific extra mutation rounds."""
