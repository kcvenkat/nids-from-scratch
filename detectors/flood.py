from .utils import get_window_count, attack_state, unique_ports_dst, get_unique_hosts
from server.actions.alert import alert
import time

class FloodDetector:
    FLOOD_RULES = {
        #event_type: max packets allowed per window, name of flood
        "ICMP:8": {"threshold": 500, "message": "ICMP Echo Flood"},
        "TCP:S": {"threshold": 2000, "message": "TCP SYN Flood"},
        "UDP": {"threshold": 5000, "message": "UDP Flood"},
    }

    def __init__(self, flood_window = 5):
        self.WINDOW = flood_window

    def detect_flood(self, src_ip, dst_ip, event_type):
        if unique_ports_dst(src_ip, dst_ip, event_type, self.WINDOW) >= 3:
            return False
        if event_type not in self.FLOOD_RULES:
            return False
        count = get_window_count(src_ip, event_type, self.WINDOW)
        threshold = self.FLOOD_RULES[event_type]["threshold"]
        message = self.FLOOD_RULES[event_type]["message"]
        if count > threshold:
            if not attack_state[src_ip][message]:
                attack_state[src_ip][message] = True
                alert(src_ip, dst_ip, event_type, message)
                return True
        else:
            attack_state[src_ip][message] = False
        return False
    
    def add_rule(self, event_type, packet_threshold, message = None):
        if event_type in self.FLOOD_RULES:
            return False
        else:
            self.FLOOD_RULES[event_type] = {"threshold": packet_threshold, "message": message if message else event_type}
            return True
    
    def delete_rule(self, event_type):
        return self.FLOOD_RULES.pop(event_type, None)
    
    def edit_rule(self, event_type, packet_threshold, message = None):
        if event_type in self.FLOOD_RULES:
            self.FLOOD_RULES[event_type] = {"threshold": packet_threshold, "message": message if message else event_type}
            return True
        return False
    
    def change_default_window(self, new_window):
        self.WINDOW = new_window
    