from dataclasses import dataclass

@dataclass
class Event:
    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    event_type: str
    src_port: str | None = None
    dst_port: str | None = None
    flags: str | None = None
    icmp_type: int | None = None
    arp_op: int | None = None

    @property
    def conn(self):
        if self.src_port is None or self.dst_port is None:
            return None
        
        return (
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port
        )