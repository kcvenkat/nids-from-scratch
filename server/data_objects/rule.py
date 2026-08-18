from dataclasses import dataclass, field


@dataclass
class Rule:
    sid: int
    action: str
    protocol: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    options: dict[str, str] | None = None

RULE_OBJECTS = []

def get_available_sid():
    highest_sid = 0
    for rule in RULE_OBJECTS:
        if highest_sid < rule.sid:
            highest_sid = rule.sid
    
    return highest_sid + 1

# Supported rule options:
# - msg: alert/log message text
# - flags: TCP flags filter (for example: S)
# - icmp_type: ICMP type filter
# - arp_op: ARP operation filter
# - flow: flow state filter (stateless, established, half_open, to_server, to_client)
# - track: aggregation key (by_src, by_dst)
# - threshold_type: threshold metric (count, ports, hosts)
# - count: threshold count for count-based evaluation
# - time_frame: window size in seconds for threshold evaluation
# - threshold: suppression window in seconds for alert/log rate limiting

#ex. alert tcp any any -> any any (flags: S; track: by_src; threshold_type: count; count: 10; time_frame: 5; msg: "SYN Scan detected")