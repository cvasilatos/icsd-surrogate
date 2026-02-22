"""Tests for proteus.results.packet_struct."""

from proteus.model.field_behavior import FieldBehavior
from proteus.model.raw_field import RawField
from proteus.results.packet_struct import PacketStruct


def _make_field(name: str, behavior: FieldBehavior = FieldBehavior.UNKNOWN) -> RawField:
    return RawField(
        name=name,
        relative_pos=0,
        size=1,
        val="01",
        behavior=behavior,
        accepted=False,
    )


class TestPacketStruct:
    """Tests for PacketStruct.print_plan."""

    def test_print_plan_runs_without_error(self, capsys) -> None:
        ps = PacketStruct()
        fields = [
            _make_field("modbus.func_code", FieldBehavior.FUZZABLE),
            _make_field("mbtcp.len", FieldBehavior.CONSTRAINED),
            _make_field("mbtcp.trans_id", FieldBehavior.CALCULATED),
        ]
        # Should not raise
        ps.print_plan(fields)

    def test_print_plan_with_empty_list(self) -> None:
        ps = PacketStruct()
        ps.print_plan([])

    def test_print_plan_with_valid_values(self) -> None:
        ps = PacketStruct()
        field = RawField(
            name="modbus.func_code",
            relative_pos=0,
            size=1,
            val="03",
            behavior=FieldBehavior.FUZZABLE,
            valid_values=["01", "02", "03"],
            invalid_values={"Timeout": ["ff"]},
            accepted=True,
        )
        ps.print_plan([field])
