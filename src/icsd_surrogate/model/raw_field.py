import json
from dataclasses import dataclass, field
from enum import Enum

from icsd_surrogate.model.field_behavior import FieldBehavior


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o: FieldBehavior) -> str:
        if isinstance(o, Enum):
            return o.value
        return super().default(o)


@dataclass
class RawField:
    name: str = field(default="")
    wireshark_name: str = field(default="")
    display_name: str = field(default="")
    pos: int = field(default=0)
    relative_pos: int = field(default=0)
    size: int = field(default=0)
    val: str = field(default="")
    valid_values: list[str] = field(default_factory=list, init=True)
    invalid_values: dict[str, list[str]] = field(default_factory=dict, init=True)
    layer: str = field(default="")
    behavior: FieldBehavior = field(default=FieldBehavior.UNKNOWN)
    accepted: bool = field(default=False)

    def set_behavior(self, behavior: FieldBehavior) -> None:
        if self.behavior == FieldBehavior.UNKNOWN:
            self.behavior = behavior

    def get_biggest_invalid_category_size(self) -> int:
        max_size = 0
        for values in self.invalid_values.values():
            max_size = max(max_size, len(values))
        return max_size

    def __str__(self) -> str:
        c_green = "\033[32m"
        c_yellow = "\033[33m"
        c_blue = "\033[34m"
        c_magenta = "\033[35m"
        c_cyan = "\033[36m"
        c_red = "\033[31m"
        c_white = "\033[37m"
        reset = "\033[0m"

        return (
            f"  {c_green}RawField: {self.name}, "
            f"  {c_yellow}W_Name: {self.wireshark_name}, "
            f"  {c_blue}Layer: {self.layer}, "
            f"  {c_magenta}D_Name: {self.display_name}, "
            f"  {c_cyan}Pos: {self.pos} (+{self.relative_pos}), "
            f"  {c_red}Size: {self.size}, "
            f"  {c_white}Behavior: {self.behavior.value}, "
            f"  {c_green}Accepted: {self.accepted}{reset}"
        )
