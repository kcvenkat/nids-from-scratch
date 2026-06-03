from .utils import get_half_open_tcp, get_unique_ports, attack_state
from server.alert import alert

SCAN_RULES = {
    #event_type: port threshold, message
    "TCP:S": {"ports": 300, "half_open": 200, "message": "TCP SYN Scan"},
    "TCP:FPU": {"ports": 100, "half_open": None, "message": "XMAS Scan"},
    "TCP:": {"ports": 50, "half_open": None, "message": "NULL Scan"},
    "TCP:F": {"ports": 300, "half_open": None, "message": "FIN Scan"}
}
def detect_port_scan(src_ip, dst_ip, event_type):
    if event_type not in SCAN_RULES:
        return False
    
    ports = get_unique_ports(src_ip, 30)
    half_open = get_half_open_tcp(src_ip)

    port_threshold = SCAN_RULES[event_type]["ports"]
    message = SCAN_RULES[event_type]["message"]

    required_half_open = SCAN_RULES[event_type]["half_open"]

    if ports >= port_threshold and (required_half_open is None or half_open >= required_half_open):
        if not attack_state[src_ip][message]:
            attack_state[src_ip][message] = True
            alert(src_ip, dst_ip, event_type, message)
            return True
    else:
        attack_state[src_ip][message] = False
    return False
