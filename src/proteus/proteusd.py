import json
import logging
import secrets
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, cast

import click
from cursusd.starter import Starter
from decimalog.logger import CustomLogger
from praetor.praetord import ValidatorBase
from praetor.protocol_info import ProtocolInfo

from proteus.analyzers.dynamic_field_analyzer import DynamicFieldAnalyzer
from proteus.analyzers.protocol_explorer import ProtocolExplorer
from proteus.model.cli_branding import CliBranding
from proteus.model.raw_field import EnhancedJSONEncoder, FieldBehavior, RawField
from proteus.protocols.registry import ProtocolAdapterRegistry
from proteus.results.packet_struct import PacketStruct
from proteus.utils.constants import DEFAULT_HOST, VALIDATION_TIMEOUT
from proteus.utils.packet_manipulator import construct_prefix
from proteus.utils.response_validator import is_valid_response
from proteus.utils.socket_manager import SocketManager

if TYPE_CHECKING:
    from proteus.protocols.base import ProtocolAdapter


class ProtocolFuzzer:
    """Main class for the Protocol Fuzzer.

    Responsible for loading seed packets, analyzing them to extract protocol fields, and applying fuzzing strategies based on the analysis
    results. It manages the overall workflow of the fuzzing process, including validation of seeds, dissection of packets, and generation
    of new test cases based on identified field behaviors and structural variants.
    """

    def __init__(self, protocol: str, seed: str) -> None:
        """Initialize the ProtocolFuzzer.

        Args:
            protocol: The name of the protocol to fuzz (e.g., "mbtcp", "s7comm", "dnp3").
            seed: The seed packet to use for fuzzing.

        Returns:
            None

        Attributes:
            logger: Custom logger for logging information, warnings, and errors during the fuzzing process.
            _protocol_info: ProtocolInfo object containing details about the target protocol.
            _validator: ValidatorBase object for validating seed packets against the protocol specifications.
            _packet_struct_viewer: PacketStruct object for visualizing the structure of packets and their fields.

        """
        self.logger: CustomLogger = cast("CustomLogger", logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}"))

        self.logger.debug(f"[+] Initializing Protocol Fuzzer for protocol: {protocol}")

        server_starter = Starter(protocol, self._protocol_info.custom_port, delay=3)
        server_starter.start_server()

        self._protocol_info: ProtocolInfo = ProtocolInfo.from_name(protocol)
        self._validator = ValidatorBase(protocol)
        self._adapter: ProtocolAdapter = ProtocolAdapterRegistry.get(protocol)

        self._packet_struct_viewer = PacketStruct()

        self._explorer = ProtocolExplorer(seed, self._protocol_info.name)
        self._explorer.dissect()

        self._analyzer = DynamicFieldAnalyzer(self._protocol_info.protocol_name)
        self._analyzer.analyze(seed, self._explorer.raw_fields)

    def analyze_and_fuzz(self, seed: str) -> None:
        """Analyze the provided seed packet to extract protocol fields and their behaviors, then apply fuzzing strategies based on the analysis results.

        This includes dissecting the packet, classifying fields, generating new test cases based on structural variants,
        and validating the new test cases against the target server to identify potential vulnerabilities.
        """
        self.logger.info(f"[+] Analyzing seed packet: {seed}")

        self._analyzer.cluster_responses_plotly(seed)

        self._packet_struct_viewer.print_plan(self._explorer.raw_fields)

        with Path(f"outputs/{self._protocol_info.name}_raw_fields.json").open("w") as f:
            json.dump([asdict(u) for u in self._explorer.raw_fields], f, indent=4, cls=EnhancedJSONEncoder)

        self.logger.info(f"[+] Saved raw fields to outputs/{self._protocol_info.name}_raw_fields.json")

    def _find_structural_variants(self, fields_json: list[RawField]) -> list[str]:
        pivot_field: RawField = self._find_pivot_field(fields_json)
        length_fields: list[RawField] = self._identify_length_fields(fields_json, pivot_field)
        new_seeds: list[str] = self._generate_variant_candidates(fields_json, pivot_field, length_fields)

        self._find_structural_variants2(new_seeds, pivot_field)
        return new_seeds

    def _find_pivot_field(self, fields: list[RawField]) -> RawField:
        for field in fields:
            if self._adapter.pivot_field_name in field.name:
                return field
        raise ValueError("No suitable pivot field found for structural analysis.")

    def _identify_length_fields(self, fields: list[RawField], pivot_field: RawField) -> list[RawField]:
        return [f for f in fields if f.behavior == FieldBehavior.CONSTRAINED and f.relative_pos < pivot_field.relative_pos]

    def _generate_variant_candidates(self, fields: list[RawField], pivot_field: RawField, length_fields: list[RawField]) -> list[str]:
        new_seeds: list[str] = []

        for val in self._adapter.structural_function_codes:
            base_packet: bytes = construct_prefix(fields, stop_at_name=pivot_field.name)
            base_packet += bytes.fromhex(val)

            for payload_len in self._adapter.structural_payload_lengths:
                payload: bytes = b"\x00" * payload_len
                candidate_pkt: bytes = base_packet + payload

                for len_field in length_fields:
                    candidate_pkt: bytes = self._adapter.fix_length_field(candidate_pkt, len_field)

                try:
                    self._validate_seed(DEFAULT_HOST, self._protocol_info.port, candidate_pkt)
                    new_seeds.append(candidate_pkt.hex())
                except ValueError as e:
                    self.logger.trace(f"Validation failed for candidate packet: {candidate_pkt.hex()} - Error: {e}")

        return new_seeds

    def _find_structural_variants2(self, new_seeds: list[str], pivot_field: RawField) -> None:
        for seed in new_seeds:
            explorer = ProtocolExplorer(seed, self._protocol_info.name)
            explorer.dissect()

            analyzer = DynamicFieldAnalyzer(self._protocol_info.name)
            analyzer.analyze(seed, explorer.raw_fields)

            self._packet_struct_viewer.print_plan(explorer.raw_fields)
            mutated_packet = seed
            for field in explorer.raw_fields:
                if field.behavior == FieldBehavior.FUZZABLE and field.name != pivot_field.name:
                    self.logger.info(f"Mutating field {field.name} at pos {field.relative_pos} with size {field.size}")
                    mutated_val = secrets.token_hex(field.size)
                    mutated_packet = mutated_packet[: field.relative_pos * 2] + mutated_val + mutated_packet[(field.relative_pos + field.size) * 2 :]

            self.logger.info(f"Testing mutation for all fuzzable fields: {mutated_packet}")

    def _validate_seed(self, target_ip: str, target_port: int, seed_bytes: bytes) -> dict:
        with SocketManager(target_ip, target_port, timeout=VALIDATION_TIMEOUT) as sock_mgr:
            sock_mgr.send(seed_bytes)
            response: bytes = sock_mgr.receive()

            if not is_valid_response(response):
                raise ValueError("Received invalid response")

            self.logger.debug(f"Sent: {seed_bytes.hex()} | Received: {response.hex()}")
            self._validator.validate(seed_bytes.hex(), is_request=True)

        return {"status": "RESPONSE_RECEIVED", "valid": True, "len": len(response), "data": response.hex()}


@click.command()
@click.option("--protocol", required=True, help="Protocol to use (e.g., mbtcp, s7comm, dnp3)")
@click.option("--seed", required=True, help="Hex string of the seed packet")
@click.option("--log-level", default="INFO", show_default=True, help="Logging level")
def run(protocol: str, seed: str, log_level: str) -> None:
    """Initiate Main entry point for the Protocol Fuzzer CLI."""
    CustomLogger.setup_logging("logs", "app", level=log_level)

    cli_branding = CliBranding()
    cli_branding.show_intro()

    fuzzer = ProtocolFuzzer(protocol, seed)

    fuzzer.analyze_and_fuzz(seed)


if __name__ == "__main__":
    run()
