from .utils import get_half_open_tcp, get_unique_ports, attack_state, get_unique_hosts
from server.alert import alert
class PortScanDetector:
    PORT_SCAN_RULES = {
        #event_type: {port threshold, half open connections allowed, message}
        "TCP:S": {"ports": 300, "half_open": 200, "message": "TCP SYN Scan"},
        "TCP:FPU": {"ports": 100, "half_open": None, "message": "XMAS Scan"},
        "TCP:": {"ports": 50, "half_open": None, "message": "NULL Scan"},
        "TCP:F": {"ports": 300, "half_open": None, "message": "FIN Scan"},
        "TCP:A": {"ports": 300, "half_open": None, "message": "ACK Scan"},
        "TCP:FA": {"ports": 50, "half_open": None, "message": "Maimon Scan"},
        "UDP": {"ports": 100, "half_open": None, "message": "UDP Scan"}
    }

    def __init__(self, scan_threshold = 300, scan_window = 30, lower_port_threshold = 20):
        self.GENERIC_SCAN_THRESHOLD = scan_threshold
        self.LOWER_PORT_THRESHOLD = lower_port_threshold
        self.WINDOW = scan_window

    def detect(self, src_ip, dst_ip, event_type):    
        ports = get_unique_ports(src_ip, event_type, self.WINDOW)
        half_open = get_half_open_tcp(src_ip)

        #TODO: Better solution than port scan disabling
        known_scan_active = any(
            attack_state[src_ip][rule["message"]]
            for rule in self.PORT_SCAN_RULES.values()
        )

        if event_type not in self.PORT_SCAN_RULES:
            if not known_scan_active:
                if ports >= self.GENERIC_SCAN_THRESHOLD:
                    if not attack_state[src_ip]["Port Scan"]:
                            attack_state[src_ip]["Port Scan"] = True
                            alert(src_ip, dst_ip, "", "Port Scan")
                            return True
                elif ports < self.LOWER_PORT_THRESHOLD:
                    attack_state[src_ip]["Port Scan"] = False
            return False
            
        port_threshold = self.PORT_SCAN_RULES[event_type]["ports"]
        message = self.PORT_SCAN_RULES[event_type]["message"]
        required_half_open = self.PORT_SCAN_RULES[event_type]["half_open"]

        if ports >= port_threshold and (required_half_open is None or half_open >= required_half_open):
            if not attack_state[src_ip][message]:
                attack_state[src_ip][message] = True
                alert(src_ip, dst_ip, event_type, message)
                return True 
        else:
            attack_state[src_ip][message] = False
        return False

    def add_rule(self, event_type, port_threshold, half_open = None, message = None):
        if event_type in self.PORT_SCAN_RULES:
            return False
        else:
            self.PORT_SCAN_RULES[event_type] = {"ports": port_threshold, "half_open": half_open, "message": message if message else event_type}
            return True
        
    def delete_rule(self, event_type):
        return self.PORT_SCAN_RULES.pop(event_type, None)
    
    def edit_rule(self, event_type, port_threshold, half_open = None, message = None):
        if event_type in self.PORT_SCAN_RULES:
            self.PORT_SCAN_RULES[event_type] = {"ports": port_threshold, "half_open": half_open, "message": message if message else event_type}
            return True
        return False
    
    def change_default_threshold(self, new_threshold):
        self.GENERIC_SCAN_THRESHOLD = new_threshold

    def change_default_window(self, new_window):
        self.WINDOW = new_window

class HostScanDetector:
    HOST_SCAN_RULES = {
        #event_type: hosts, ping sweep
        "ICMP:8":  {"hosts": 10, "message": "Ping Sweep"},
        "ICMP:13": {"hosts": 10, "message": "ICMP Timestamp Sweep"},
        "ICMP:17": {"hosts": 10, "message": "ICMP Netmask Sweep"},
        "ICMP:5":  {"hosts": 5,  "message": "ICMP Redirect Attack"},
    }

    def __init__(self, scan_threshold = 300, scan_window = 30, lower_host_threshold = 5):
        self.GENERIC_SCAN_THRESHOLD = scan_threshold
        self.LOWER_HOST_THRESHOLD = lower_host_threshold
        self.WINDOW = scan_window

    def detect(self, src_ip, dst_ip, event_type):
        if event_type not in self.HOST_SCAN_RULES:
            return False
        
        host_threshold = self.HOST_SCAN_RULES[event_type]["hosts"]
        message = self.HOST_SCAN_RULES[event_type]["message"]
        hosts = get_unique_hosts(src_ip, self.WINDOW)

        if hosts >= host_threshold:
            if not attack_state[src_ip][message]:
                attack_state[src_ip][message] = True
                alert(src_ip, dst_ip, event_type, message)
                return True
        elif hosts < self.LOWER_HOST_THRESHOLD:
            attack_state[src_ip][message] = False
        return False

    def add_rule(self, event_type, host_threshold, message = None):
        if event_type in self.HOST_SCAN_RULES:
            return False
        else:
            self.HOST_SCAN_RULES[event_type] = {"hosts": host_threshold, "message": message if message else event_type}
            return True
        
    def delete_rule(self, event_type):
        return self.HOST_SCAN_RULES.pop(event_type, None)
    
    def edit_rule(self, event_type, host_threshold, message = None):
        if event_type in self.HOST_SCAN_RULES:
            self.HOST_SCAN_RULES[event_type] = {"hosts": host_threshold, "message": message if message else event_type}
            return True
        return False

    def change_default_window(self, new_window):
        self.WINDOW = new_window