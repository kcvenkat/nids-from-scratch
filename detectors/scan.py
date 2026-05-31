from .utils import get_half_open_tcp, get_unique_ports, attack_state
from server.alert import alert

def detect_syn_scan(src_ip, dst_ip, event_type):
    if event_type != "TCP:S":
        return False
    
    ports = get_unique_ports(src_ip, 30)
    half_open = get_half_open_tcp(src_ip)

    if ports == 100 and half_open == 50:
        if not attack_state[src_ip]["syn_scan"]:
            attack_state[src_ip]["syn_scan"] = True
            alert(src_ip, dst_ip, event_type, "TCP SYN Scan")
            return True
    else:
        attack_state[src_ip]["syn_scan"] = False
    return False
