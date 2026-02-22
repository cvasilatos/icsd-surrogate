"""Tests for proteus.analyzers package (DynamicFieldAnalyzer and ProtocolExplorer)."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Stub out the unavailable 'praetor' third-party package so the analyzer
# modules can be imported without a live installation.
# MagicMock() instances are used (not the class) so attribute access on
# the stubs (e.g. stub.ValidatorBase) returns auto-created MagicMock
# attributes, and calling them (e.g. ValidatorBase("mbtcp")) always returns
# a MagicMock without any unintended spec inference.
# ---------------------------------------------------------------------------
sys.modules.setdefault("praetor", MagicMock())
sys.modules.setdefault("praetor.praetord", MagicMock())
sys.modules.setdefault("praetor.protocol_info", MagicMock())

# Now safe to import the analyzers.
from proteus.analyzers.dynamic_field_analyzer import DynamicFieldAnalyzer  # noqa: E402
from proteus.analyzers.protocol_explorer import ProtocolExplorer  # noqa: E402
from proteus.model.raw_field import FieldBehavior, RawField  # noqa: E402
from proteus.utils.constants import CONSTRAINED_THRESHOLD, DEFAULT_MUTATION_SAMPLE_SIZE  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_protocol_info(port: int = 502, name: str = "mbtcp", scapy_names: list[str] | None = None) -> MagicMock:
    info = MagicMock()
    info.custom_port = port
    info.protocol_name = name
    info.name = name
    info.scapy_names = scapy_names if scapy_names is not None else [name, "modbus"]
    return info


def _make_mock_logger() -> MagicMock:
    return MagicMock()


def _make_dynamic_analyzer(
    protocol: str = "mbtcp",
    *,
    receive_response: bytes = b"\x01\x03\x02\x00\x01",
    scapy_names: list[str] | None = None,
) -> tuple[DynamicFieldAnalyzer, MagicMock]:
    """Return a (DynamicFieldAnalyzer, mock_socket_instance) pair with all external deps patched."""
    mock_logger = _make_mock_logger()
    mock_sock = MagicMock()
    mock_sock.receive.return_value = receive_response

    with (
        patch("proteus.analyzers.dynamic_field_analyzer.SocketManager", return_value=mock_sock),
        patch("proteus.analyzers.dynamic_field_analyzer.ProtocolInfo") as mock_pi,
        patch("proteus.analyzers.dynamic_field_analyzer.ProtocolAdapterRegistry"),
        patch("logging.getLogger", return_value=mock_logger),
    ):
        mock_pi.from_name.return_value = _make_protocol_info(scapy_names=scapy_names)
        analyzer = DynamicFieldAnalyzer(protocol)
        analyzer._sock = mock_sock  # keep a direct reference for assertions
    return analyzer, mock_sock


def _make_explorer(
    packet: str = "000100000006",
    proto_filter: str = "mbtcp",
    *,
    receive_response: bytes = b"\x01\x03\x02\x00\x01",
    scapy_names: list[str] | None = None,
) -> tuple[ProtocolExplorer, MagicMock, MagicMock]:
    """Return (ProtocolExplorer, mock_socket_instance, mock_validator_instance)."""
    mock_logger = _make_mock_logger()
    mock_sock = MagicMock()
    mock_sock.receive.return_value = receive_response
    mock_validator = MagicMock()

    with (
        patch("proteus.analyzers.protocol_explorer.SocketManager", return_value=mock_sock),
        patch("proteus.analyzers.protocol_explorer.ValidatorBase", return_value=mock_validator),
        patch("proteus.analyzers.protocol_explorer.ProtocolInfo") as mock_pi,
        patch("logging.getLogger", return_value=mock_logger),
    ):
        mock_pi.from_name.return_value = _make_protocol_info(scapy_names=scapy_names)
        explorer = ProtocolExplorer(packet, proto_filter)
    return explorer, mock_sock, mock_validator


def _make_layer_field(name: str, pos: int, size: int, raw_value: str) -> MagicMock:
    """Create a minimal mock that looks like a ``pyshark`` LayerField."""
    f = MagicMock()
    f.name = name
    f.showname = f"{name}: {raw_value}"
    f.showname_value = raw_value
    f.pos = str(pos)
    f.size = str(size)
    f.raw_value = raw_value
    f.all_fields = [f]
    return f


def _make_layer(layer_name: str, fields: list[MagicMock]) -> MagicMock:
    """Create a mock pyshark layer whose get_field returns the supplied fields by index."""
    layer = MagicMock()
    layer.layer_name = layer_name
    layer.field_names = [f.name for f in fields]

    # Map each field name to a wrapper whose .all_fields contains that field.
    field_map: dict[str, MagicMock] = {}
    for f in fields:
        wrapper = MagicMock()
        wrapper.all_fields = [f]
        field_map[f.name] = wrapper

    layer.get_field.side_effect = lambda fn: field_map[fn]
    return layer


# ===========================================================================
# DynamicFieldAnalyzer._get_random_combinations
# ===========================================================================


class TestGetRandomCombinations:
    """Unit tests for DynamicFieldAnalyzer._get_random_combinations."""

    def setup_method(self) -> None:
        mock_logger = _make_mock_logger()
        with (
            patch("proteus.analyzers.dynamic_field_analyzer.SocketManager"),
            patch("proteus.analyzers.dynamic_field_analyzer.ProtocolInfo") as mock_pi,
            patch("proteus.analyzers.dynamic_field_analyzer.ProtocolAdapterRegistry"),
            patch("logging.getLogger", return_value=mock_logger),
        ):
            mock_pi.from_name.return_value = _make_protocol_info()
            self.analyzer = DynamicFieldAnalyzer("mbtcp")

    def test_returns_list_of_tuples(self) -> None:
        result = self.analyzer._get_random_combinations(2, 5)
        assert isinstance(result, list)
        assert all(isinstance(c, tuple) for c in result)

    def test_tuple_length_matches_num_bytes(self) -> None:
        for num_bytes in (1, 2, 3):
            result = self.analyzer._get_random_combinations(num_bytes, 4)
            assert all(len(t) == num_bytes for t in result)

    def test_sample_size_respected(self) -> None:
        result = self.analyzer._get_random_combinations(2, 10)
        assert len(result) == 10  # noqa: PLR2004

    def test_sample_size_capped_at_total_possibilities(self) -> None:
        """A 1-byte field has only 256 possible values; sample_size should be capped."""
        result = self.analyzer._get_random_combinations(1, 9999)
        assert len(result) == 256  # noqa: PLR2004

    def test_uses_default_sample_size(self) -> None:
        result = self.analyzer._get_random_combinations(2)
        assert len(result) == DEFAULT_MUTATION_SAMPLE_SIZE

    def test_byte_values_are_in_valid_range(self) -> None:
        result = self.analyzer._get_random_combinations(2, 100)
        for combo in result:
            assert all(0 <= b <= 255 for b in combo)  # noqa: PLR2004


# ===========================================================================
# DynamicFieldAnalyzer.cluster_responses_plotly
# ===========================================================================


class TestClusterResponsesPlotly:
    """Unit tests for DynamicFieldAnalyzer.cluster_responses_plotly."""

    def setup_method(self) -> None:
        mock_logger = _make_mock_logger()
        with (
            patch("proteus.analyzers.dynamic_field_analyzer.SocketManager"),
            patch("proteus.analyzers.dynamic_field_analyzer.ProtocolInfo") as mock_pi,
            patch("proteus.analyzers.dynamic_field_analyzer.ProtocolAdapterRegistry"),
            patch("logging.getLogger", return_value=mock_logger),
        ):
            mock_pi.from_name.return_value = _make_protocol_info()
            self.analyzer = DynamicFieldAnalyzer("mbtcp")

    def _run(self, requests: list[str] = (), responses: list[str] = ()) -> MagicMock:
        self.analyzer._requests = list(requests)
        self.analyzer._responses = list(responses)
        mock_fig = MagicMock()
        with patch("proteus.analyzers.dynamic_field_analyzer.go.Figure", return_value=mock_fig):
            self.analyzer.cluster_responses_plotly("0102030405")
        return mock_fig

    def test_show_is_called(self) -> None:
        mock_fig = self._run()
        mock_fig.show.assert_called_once()

    def test_layout_is_updated(self) -> None:
        mock_fig = self._run()
        mock_fig.update_layout.assert_called_once()

    def test_with_empty_data(self) -> None:
        """No requests or responses should not raise."""
        mock_fig = self._run([], [])
        mock_fig.show.assert_called_once()

    def test_request_trace_added(self) -> None:
        """When requests are present at least one trace is added."""
        mock_fig = self._run(requests=["0102030405"])
        assert mock_fig.add_trace.call_count >= 1

    def test_response_classified_as_exception_when_short(self) -> None:
        """A response shorter than 60 % of seed length is labelled 'Likely Exception'."""
        seed = "01020304050607080910"  # 10 bytes
        short_resp = "0102"  # 1 byte — well below 60 %
        self.analyzer._requests = []
        self.analyzer._responses = [short_resp]
        mock_fig = MagicMock()
        with patch("proteus.analyzers.dynamic_field_analyzer.go.Figure", return_value=mock_fig):
            self.analyzer.cluster_responses_plotly(seed)
        mock_fig.show.assert_called_once()

    def test_response_classified_as_valid_variation(self) -> None:
        """A response very similar to the seed is labelled 'Valid Variation'."""
        seed = "01020304050607080910"
        similar = "01020304050607080911"  # only last byte differs
        self.analyzer._requests = []
        self.analyzer._responses = [similar]
        mock_fig = MagicMock()
        with patch("proteus.analyzers.dynamic_field_analyzer.go.Figure", return_value=mock_fig):
            self.analyzer.cluster_responses_plotly(seed)
        mock_fig.show.assert_called_once()

    def test_response_classified_as_outlier(self) -> None:
        """A response that is long enough but dissimilar is labelled 'Unknown / Outlier'."""
        seed = "0102030405060708"  # 8 bytes
        # Same length (not a short exception) but very different content (low similarity).
        outlier = "deadbeefcafe0001"
        self.analyzer._requests = []
        self.analyzer._responses = [outlier]
        mock_fig = MagicMock()
        with patch("proteus.analyzers.dynamic_field_analyzer.go.Figure", return_value=mock_fig):
            self.analyzer.cluster_responses_plotly(seed)
        mock_fig.show.assert_called_once()


# ===========================================================================
# DynamicFieldAnalyzer.analyze
# ===========================================================================


class TestAnalyze:
    """Unit tests for DynamicFieldAnalyzer.analyze."""

    def _make_analyzer(self, *, receive_response: bytes = b"\x01\x03\x02\x00\x01") -> tuple[DynamicFieldAnalyzer, MagicMock]:
        mock_logger = _make_mock_logger()
        mock_sock = MagicMock()
        mock_sock.receive.return_value = receive_response
        mock_adapter = MagicMock()
        mock_adapter.get_additional_mutations.return_value = []

        with (
            patch("proteus.analyzers.dynamic_field_analyzer.SocketManager", return_value=mock_sock),
            patch("proteus.analyzers.dynamic_field_analyzer.ProtocolInfo") as mock_pi,
            patch("proteus.analyzers.dynamic_field_analyzer.ProtocolAdapterRegistry") as mock_reg,
            patch("logging.getLogger", return_value=mock_logger),
        ):
            mock_pi.from_name.return_value = _make_protocol_info()
            mock_reg.get.return_value = mock_adapter
            analyzer = DynamicFieldAnalyzer("mbtcp")
            analyzer._adapter = mock_adapter
        return analyzer, mock_sock

    def test_skips_calculated_fields(self) -> None:
        analyzer, mock_sock = self._make_analyzer()
        seed = "000100000006011000100002"
        field = RawField(name="checksum", val="0001", relative_pos=0, size=2, behavior=FieldBehavior.CALCULATED)

        with patch("proteus.analyzers.dynamic_field_analyzer.PacketManipulator") as mock_pm:
            analyzer.analyze(seed, [field])
            mock_pm.inject_mutation.assert_not_called()
        assert field.behavior is FieldBehavior.CALCULATED

    def test_fuzzable_classification_on_valid_response(self) -> None:
        """Field becomes FUZZABLE when a valid response is received."""
        analyzer, mock_sock = self._make_analyzer(receive_response=b"\x01\x03\x02\x00\x01")
        seed = "000100000006011000100002"
        field = RawField(name="mbtcp.trans_id", val="0001", relative_pos=0, size=2)

        with patch("proteus.analyzers.dynamic_field_analyzer.PacketManipulator") as mock_pm:
            mock_pm.inject_mutation.return_value = bytearray(bytes.fromhex(seed))
            analyzer.analyze(seed, [field])

        assert field.behavior is FieldBehavior.FUZZABLE

    def test_constrained_classification_when_many_invalid(self) -> None:
        """Field becomes CONSTRAINED when the invalid-value category is large and no valid responses."""
        analyzer, mock_sock = self._make_analyzer(receive_response=bytes.fromhex("0000aabbcc"))
        seed = "000100000006011000100002"
        field = RawField(name="modbus.data", val="0001", relative_pos=8, size=2)

        # Pre-populate invalid values beyond the constrained threshold.
        field.invalid_values["Timeout"] = [f"{i:04x}" for i in range(CONSTRAINED_THRESHOLD + 2)]

        with patch("proteus.analyzers.dynamic_field_analyzer.PacketManipulator") as mock_pm:
            mock_pm.inject_mutation.return_value = bytearray(bytes.fromhex(seed))
            analyzer.analyze(seed, [field])

        assert field.behavior is FieldBehavior.CONSTRAINED

    def test_exception_triggers_reconnect(self) -> None:
        """An exception during mutation causes socket.reconnect() to be called."""
        analyzer, mock_sock = self._make_analyzer()
        seed = "000100000006011000100002"
        field = RawField(name="modbus.data", val="0001", relative_pos=8, size=2)

        with patch("proteus.analyzers.dynamic_field_analyzer.PacketManipulator") as mock_pm:
            mock_pm.inject_mutation.side_effect = RuntimeError("connection lost")
            analyzer.analyze(seed, [field])

        mock_sock.reconnect.assert_called()

    def test_exception_stored_in_invalid_values(self) -> None:
        """Exception message is used as the key in field.invalid_values."""
        analyzer, mock_sock = self._make_analyzer()
        seed = "000100000006011000100002"
        field = RawField(name="modbus.data", val="0001", relative_pos=8, size=2)

        with patch("proteus.analyzers.dynamic_field_analyzer.PacketManipulator") as mock_pm:
            mock_pm.inject_mutation.side_effect = ValueError("bad value")
            analyzer.analyze(seed, [field])

        assert "bad value" in field.invalid_values
        assert len(field.invalid_values["bad value"]) > 0

    def test_valid_mutation_recorded_in_requests_and_responses(self) -> None:
        analyzer, mock_sock = self._make_analyzer(receive_response=b"\x01\x03\x02\x00\x01")
        seed = "000100000006011000100002"
        field = RawField(name="mbtcp.trans_id", val="0001", relative_pos=0, size=2)

        with patch("proteus.analyzers.dynamic_field_analyzer.PacketManipulator") as mock_pm:
            mock_pm.inject_mutation.return_value = bytearray(bytes.fromhex(seed))
            analyzer.analyze(seed, [field])

        assert len(analyzer._requests) > 0
        assert len(analyzer._responses) > 0

    def test_empty_fields_list(self) -> None:
        """analyze() with no fields should complete without error."""
        analyzer, _ = self._make_analyzer()
        analyzer.analyze("0001000000060110001000020000", [])


# ===========================================================================
# DynamicFieldAnalyzer._run_additional_mutations
# ===========================================================================


class TestRunAdditionalMutations:
    """Unit tests for DynamicFieldAnalyzer._run_additional_mutations."""

    def _make_analyzer(self) -> tuple[DynamicFieldAnalyzer, MagicMock]:
        analyzer, mock_sock = _make_dynamic_analyzer()
        analyzer._adapter = MagicMock()
        analyzer._socket_manager = mock_sock
        return analyzer, mock_sock

    def test_sends_each_additional_mutation(self) -> None:
        analyzer, mock_sock = self._make_analyzer()
        mutations = ["000100000006011000100001", "000100000006011000100002"]
        analyzer._adapter.get_additional_mutations.return_value = mutations

        analyzer._run_additional_mutations([], "000100000006011000100002")

        assert mock_sock.send.call_count == len(mutations)

    def test_responses_appended_for_each_mutation(self) -> None:
        analyzer, mock_sock = self._make_analyzer()
        mutations = ["000100000006011000100001", "000100000006011000100002"]
        analyzer._adapter.get_additional_mutations.return_value = mutations
        initial_responses = len(analyzer._responses)

        analyzer._run_additional_mutations([], "000100000006011000100002")

        assert len(analyzer._responses) == initial_responses + len(mutations)

    def test_no_additional_mutations_is_noop(self) -> None:
        analyzer, mock_sock = self._make_analyzer()
        analyzer._adapter.get_additional_mutations.return_value = []

        analyzer._run_additional_mutations([], "000100000006011000100002")

        mock_sock.send.assert_not_called()


# ===========================================================================
# ProtocolExplorer.__init__
# ===========================================================================


class TestProtocolExplorerInit:
    """Unit tests for ProtocolExplorer initialization."""

    def test_socket_connected_on_init(self) -> None:
        explorer, mock_sock, _ = _make_explorer()
        mock_sock.connect.assert_called_once()

    def test_raw_fields_initially_empty(self) -> None:
        explorer, _, _ = _make_explorer()
        assert explorer.raw_fields == []

    def test_packet_stored(self) -> None:
        packet = "000100000006"
        explorer, _, _ = _make_explorer(packet=packet)
        assert explorer._packet == packet


# ===========================================================================
# ProtocolExplorer.validate_seed
# ===========================================================================


class TestValidateSeed:
    """Unit tests for ProtocolExplorer.validate_seed."""

    def test_returns_validated_packet_on_valid_response(self) -> None:
        explorer, mock_sock, mock_validator = _make_explorer(receive_response=b"\x01\x03\x02\x00\x01")
        mock_packet = MagicMock()
        mock_validator.validate.return_value = mock_packet

        result = explorer.validate_seed()

        assert result is mock_packet

    def test_sends_seed_bytes_to_socket(self) -> None:
        packet_hex = "000100000006"
        explorer, mock_sock, mock_validator = _make_explorer(packet=packet_hex, receive_response=b"\x01\x03\x02\x00\x01")
        mock_validator.validate.return_value = MagicMock()

        explorer.validate_seed()

        mock_sock.send.assert_called_once_with(bytes.fromhex(packet_hex))

    def test_raises_value_error_on_empty_response(self) -> None:
        explorer, _, mock_validator = _make_explorer(receive_response=b"")
        mock_validator.validate.return_value = MagicMock()

        with pytest.raises(ValueError, match="No response"):
            explorer.validate_seed()

    def test_raises_value_error_on_invalid_response_prefix(self) -> None:
        explorer, _, mock_validator = _make_explorer(receive_response=bytes.fromhex("0000aabbcc"))
        mock_validator.validate.return_value = MagicMock()

        with pytest.raises(ValueError, match="No response or unexpected response"):
            explorer.validate_seed()


# ===========================================================================
# ProtocolExplorer.dissect
# ===========================================================================


class TestDissect:
    """Unit tests for ProtocolExplorer.dissect."""

    def _make_explorer_with_packet(self, mock_packet: MagicMock, scapy_names: list[str] | None = None) -> ProtocolExplorer:
        mock_logger = _make_mock_logger()
        mock_sock = MagicMock()
        mock_sock.receive.return_value = b"\x01\x03\x02\x00\x01"
        mock_validator = MagicMock()
        mock_validator.validate.return_value = mock_packet

        with (
            patch("proteus.analyzers.protocol_explorer.SocketManager", return_value=mock_sock),
            patch("proteus.analyzers.protocol_explorer.ValidatorBase", return_value=mock_validator),
            patch("proteus.analyzers.protocol_explorer.ProtocolInfo") as mock_pi,
            patch("logging.getLogger", return_value=mock_logger),
        ):
            mock_pi.from_name.return_value = _make_protocol_info(scapy_names=scapy_names or ["mbtcp"])
            explorer = ProtocolExplorer("000100000006", "mbtcp")
        return explorer

    def test_extracts_fields_from_matching_layer(self) -> None:
        f1 = _make_layer_field("mbtcp.trans_id", 1, 2, "0001")
        f2 = _make_layer_field("mbtcp.proto_id", 3, 2, "0000")
        layer = _make_layer("mbtcp", [f1, f2])
        mock_packet = MagicMock()
        mock_packet.layers = [layer]

        explorer = self._make_explorer_with_packet(mock_packet)
        explorer.dissect()

        assert len(explorer.raw_fields) == 2  # noqa: PLR2004
        names = [rf.name for rf in explorer.raw_fields]
        assert "mbtcp.trans_id" in names
        assert "mbtcp.proto_id" in names

    def test_skips_non_matching_layers(self) -> None:
        f1 = _make_layer_field("eth.src", 1, 6, "aabbccddeeff")
        layer = _make_layer("eth", [f1])  # 'eth' is not in scapy_names
        mock_packet = MagicMock()
        mock_packet.layers = [layer]

        explorer = self._make_explorer_with_packet(mock_packet, scapy_names=["mbtcp"])
        explorer.dissect()

        assert explorer.raw_fields == []

    def test_fields_sorted_by_position(self) -> None:
        f1 = _make_layer_field("mbtcp.len", 5, 2, "0006")
        f2 = _make_layer_field("mbtcp.trans_id", 1, 2, "0001")
        f3 = _make_layer_field("mbtcp.proto_id", 3, 2, "0000")
        layer = _make_layer("mbtcp", [f1, f2, f3])
        mock_packet = MagicMock()
        mock_packet.layers = [layer]

        explorer = self._make_explorer_with_packet(mock_packet)
        explorer.dissect()

        positions = [rf.pos for rf in explorer.raw_fields]
        assert positions == sorted(positions)

    def test_skips_fields_with_empty_raw_value(self) -> None:
        f1 = _make_layer_field("mbtcp.trans_id", 1, 2, "0001")
        f2 = _make_layer_field("mbtcp.empty", 3, 2, "")  # empty raw_value
        layer = _make_layer("mbtcp", [f1, f2])
        mock_packet = MagicMock()
        mock_packet.layers = [layer]

        explorer = self._make_explorer_with_packet(mock_packet)
        explorer.dissect()

        names = [rf.name for rf in explorer.raw_fields]
        assert "mbtcp.empty" not in names
        assert "mbtcp.trans_id" in names

    def test_skips_fields_with_empty_name(self) -> None:
        f1 = _make_layer_field("mbtcp.trans_id", 1, 2, "0001")
        f2 = _make_layer_field("", 3, 2, "0000")  # empty name
        layer = _make_layer("mbtcp", [f1, f2])
        mock_packet = MagicMock()
        mock_packet.layers = [layer]

        explorer = self._make_explorer_with_packet(mock_packet)
        explorer.dissect()

        names = [rf.name for rf in explorer.raw_fields]
        assert "" not in names

    def test_overlapping_field_with_status_marks_previous_as_calculated(self) -> None:
        """When a 'status' field shares the same position, the previous field is marked CALCULATED."""
        f1 = _make_layer_field("mbtcp.trans_id", 1, 2, "0001")
        f2 = _make_layer_field("mbtcp.status", 1, 2, "0001")  # same pos, contains 'status'
        layer = _make_layer("mbtcp", [f1, f2])
        mock_packet = MagicMock()
        mock_packet.layers = [layer]

        explorer = self._make_explorer_with_packet(mock_packet)
        explorer.dissect()

        # The last remaining field at that position is f2 (replacement).
        # f1's behavior was set to CALCULATED before replacement.
        assert len(explorer.raw_fields) == 1

    def test_overlapping_field_replaces_previous(self) -> None:
        """A field at the same position as the previous replaces it in raw_fields."""
        f1 = _make_layer_field("mbtcp.trans_id", 1, 2, "0001")
        f2 = _make_layer_field("mbtcp.proto_id", 1, 4, "00000000")  # same pos, larger
        layer = _make_layer("mbtcp", [f1, f2])
        mock_packet = MagicMock()
        mock_packet.layers = [layer]

        explorer = self._make_explorer_with_packet(mock_packet)
        explorer.dissect()

        assert len(explorer.raw_fields) == 1
        assert explorer.raw_fields[0].name == "mbtcp.proto_id"

    def test_empty_layers(self) -> None:
        mock_packet = MagicMock()
        mock_packet.layers = []

        explorer = self._make_explorer_with_packet(mock_packet)
        explorer.dissect()

        assert explorer.raw_fields == []


# ===========================================================================
# ProtocolExplorer.raw_fields property
# ===========================================================================


class TestRawFieldsProperty:
    """Unit tests for ProtocolExplorer.raw_fields property."""

    def test_returns_list(self) -> None:
        explorer, _, _ = _make_explorer()
        assert isinstance(explorer.raw_fields, list)

    def test_returns_same_object_as_internal_state(self) -> None:
        explorer, _, _ = _make_explorer()
        explorer._raw_fields = [RawField(name="x", relative_pos=1, size=1, val="01")]
        assert explorer.raw_fields is explorer._raw_fields
