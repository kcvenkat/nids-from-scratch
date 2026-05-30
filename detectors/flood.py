from .utils import tracker, get_window_count, attack_state
from server.alert import alert
import time

#rules for flood detection. 
WINDOW = 5

FLOOD_RULES = {
    #event_type: max packets allowed per window
    "ICMP:8": {"threshold": 100, "message": "ICMP Echo Flood"},
    "TCP:S": {"threshold": 50, "message": "TCP SYN Flood"},
    "UDP": {"thredhold": 300, "message": "UDP Flood"},
}


def detect_flood(src_ip, dst_ip, event_type,):
    if event_type not in FLOOD_RULES:
        return
    tracker[src_ip][event_type].append(time.time())
    count = get_window_count(src_ip, event_type, WINDOW)
    threshold = FLOOD_RULES[event_type]["threshold"]
    message = FLOOD_RULES[event_type]["message"]
    if count > threshold:
        if not attack_state[src_ip][event_type]:
            attack_state[src_ip][event_type] = True
            alert(src_ip, dst_ip, event_type, message)
            return count
    else:
        attack_state[src_ip][event_type] = False
    return None
    