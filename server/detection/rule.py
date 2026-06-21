from dataclasses import dataclass, field

@dataclass
class Rule:
    sid: int
    action: str
    protocol: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port:str
    options: dict[str, str] | None = None

RULE_OBJECTS = []