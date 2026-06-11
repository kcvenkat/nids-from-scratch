from dataclasses import dataclass

@dataclass
class Event:
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: str | None = None
    dst_port: str | None = None
    flags: str | None = None
    icmp_type: int | None = None
    arp_op: int | None = None