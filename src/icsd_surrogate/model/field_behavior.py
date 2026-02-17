from enum import Enum


class FieldBehavior(Enum):
    UNKNOWN = "UNKNOWN"
    FUZZABLE = "FUZZABLE"
    CONSTRAINED = "CONSTRAINED"
    CALCULATED = "CALCULATED"
    WIRESHARK = "WIRESHARK"
    SERVER_ERROR = "SERVER_ERROR"

    @property
    def color(self) -> str:
        if self == FieldBehavior.FUZZABLE:
            return "green"
        if self == FieldBehavior.CONSTRAINED:
            return "yellow"
        if self == FieldBehavior.CALCULATED:
            return "blue"
        if self == FieldBehavior.WIRESHARK:
            return "red"
        if self == FieldBehavior.SERVER_ERROR:
            return "magenta"
        return "black"
