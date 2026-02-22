"""Tests for proteus.protocols.registry."""

import pytest

from proteus.protocols.dnp3 import Dnp3Adapter
from proteus.protocols.modbus import ModbusAdapter
from proteus.protocols.registry import ProtocolAdapterRegistry
from proteus.protocols.s7comm import S7CommAdapter


class TestProtocolAdapterRegistry:
    """Tests for ProtocolAdapterRegistry."""

    def test_mbtcp_is_registered(self) -> None:
        adapter = ProtocolAdapterRegistry.get("mbtcp")
        assert isinstance(adapter, ModbusAdapter)

    def test_dnp3_is_registered(self) -> None:
        adapter = ProtocolAdapterRegistry.get("dnp3")
        assert isinstance(adapter, Dnp3Adapter)

    def test_s7comm_is_registered(self) -> None:
        adapter = ProtocolAdapterRegistry.get("s7comm")
        assert isinstance(adapter, S7CommAdapter)

    def test_unknown_protocol_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="No adapter registered for protocol"):
            ProtocolAdapterRegistry.get("unknown_proto")

    def test_register_and_retrieve_custom_adapter(self) -> None:
        adapter = ModbusAdapter()
        ProtocolAdapterRegistry.register("custom_test_proto", adapter)
        assert ProtocolAdapterRegistry.get("custom_test_proto") is adapter
        # clean up to avoid polluting other tests
        del ProtocolAdapterRegistry._adapters["custom_test_proto"]

    def test_register_overwrites_existing(self) -> None:
        original = ProtocolAdapterRegistry.get("mbtcp")
        new_adapter = ModbusAdapter()
        ProtocolAdapterRegistry.register("mbtcp", new_adapter)
        assert ProtocolAdapterRegistry.get("mbtcp") is new_adapter
        # restore
        ProtocolAdapterRegistry.register("mbtcp", original)
