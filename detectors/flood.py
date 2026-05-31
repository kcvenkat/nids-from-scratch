from .utils import tracker, get_window_count, attack_state
from server.alert import alert
import time

#rules for flood detection. 
WINDOW = 5

FLOOD_RULES = {
    #event_type: max packets allowed per window, name of flood
    "ICMP:8": {"threshold": 500, "message": "ICMP Echo Flood"},
    "TCP:S": {"threshold": 1000, "message": "TCP SYN Flood"},
    "UDP": {"threshold": 2000, "message": "UDP Flood"},
}


def detect_flood(src_ip, dst_ip, event_type):
    if attack_state[src_ip]["syn_scan"]:
        return False
    if event_type not in FLOOD_RULES:
        return False
    tracker[src_ip][event_type].append(time.time())
    count = get_window_count(src_ip, event_type, WINDOW)
    threshold = FLOOD_RULES[event_type]["threshold"]
    message = FLOOD_RULES[event_type]["message"]
    if count > threshold:
        if not attack_state[src_ip][message]:
            attack_state[src_ip][message] = True
            alert(src_ip, dst_ip, event_type, message)
            return True
    else:
        attack_state[src_ip][message] = False
    return False
    