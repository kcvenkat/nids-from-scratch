from .utils import tracker, get_window_count, attack_state
from server.alert import alert
import time

def detect_flood(src_ip, dst_ip, event_type, window, threshold):
    tracker[src_ip][event_type].append(time.time())
    count = get_window_count(src_ip, event_type, window)
    if count > threshold:
        if not attack_state[src_ip][event_type]:
            attack_state[src_ip][event_type] = True
            alert(src_ip, dst_ip, event_type)
            return count
    else:
        attack_state[src_ip][event_type] = False
    return None

def detect_icmp(src_ip, dst_ip, event_type):
    if event_type == "ICMP:8":
        detect_flood(src_ip, dst_ip, event_type, 5, 100)
    