"""Protocol adapter registry with built-in registrations."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from proteus.protocols.dnp3 import Dnp3Adapter
from proteus.protocols.modbus import ModbusAdapter
from proteus.protocols.s7comm import S7CommAdapter

if TYPE_CHECKING:
    from proteus.protocols.base import ProtocolAdapter


class ProtocolAdapterRegistry:
    """Maps protocol name strings to their corresponding :class:`ProtocolAdapter` instances."""

    _adapters: ClassVar[dict[str, ProtocolAdapter]] = {}

    @classmethod
    def register(cls, name: str, adapter: ProtocolAdapter) -> None:
        """Register *adapter* under *name*."""
        cls._adapters[name] = adapter

    @classmethod
    def get(cls, protocol_name: str) -> ProtocolAdapter:
        """Return the adapter registered for *protocol_name*.

        Raises:
            ValueError: When no adapter is registered for *protocol_name*.

        """
        adapter = cls._adapters.get(protocol_name)
        if adapter is None:
            raise ValueError(f"No adapter registered for protocol: {protocol_name!r}")
        return adapter


ProtocolAdapterRegistry.register("mbtcp", ModbusAdapter())
ProtocolAdapterRegistry.register("dnp3", Dnp3Adapter())
ProtocolAdapterRegistry.register("s7comm", S7CommAdapter())
