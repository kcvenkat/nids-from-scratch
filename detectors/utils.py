#TODO: rename and move into utils folder

from collections import deque, defaultdict
import time

tracker = defaultdict(lambda: defaultdict(deque))
attack_state = defaultdict(lambda: defaultdict(bool))
port_tracker = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(deque))))
host_tracker = defaultdict(dict)
tcp_connection_tracker = {}

def get_window_count(src_ip, protocol, window):
    now = time.time()
    timestamps = tracker[src_ip][protocol]

    while timestamps and now - timestamps[0] > window:
        timestamps.popleft()

    return len(timestamps)

#unique ports overall
def get_unique_ports(src_ip, event_type, window):
    now = time.time()

    ports_hit = 0
    
    for dst_ip in port_tracker[src_ip]:
        for port, timestamps in port_tracker[src_ip][dst_ip][event_type].items():
            while timestamps and now - timestamps[0] > window:
                timestamps.popleft()
            if timestamps:
                ports_hit += 1

    return ports_hit

#unique ports on a dst_ip
def unique_ports_dst(src_ip, dst_ip, event_type, window):
    now = time.time()
    ports_hit = 0

    for port, timestamps in port_tracker[src_ip][dst_ip][event_type].items():
        while timestamps and now - timestamps[0] > window:
            timestamps.popleft()
        if timestamps:
            ports_hit += 1

    return ports_hit

def get_unique_hosts(src_ip, window):
    now = time.time()

    return sum(1 for last_seen in host_tracker[src_ip].values() if now - last_seen <=window)

def traffic_per_second(src_ip, event_type, window):
    if window <= 0:
        return 0

    count = get_window_count(src_ip, event_type, window)
    return count / window

def record_packet(src_ip, protocol):
    tracker[src_ip][protocol].append(time.time())

def record_port(src_ip, dst_ip, event_type, dst_port):
    port_tracker[src_ip][dst_ip][event_type][dst_port].append(time.time())

def record_unique_host(src_ip, dst_ip):
    host_tracker[src_ip][dst_ip] = time.time()

def record_tcp(src_ip, src_port, dst_ip, dst_port):
    conn = (src_ip, src_port, dst_ip, dst_port)

    if conn not in tcp_connection_tracker:
        tcp_connection_tracker[conn] = {
            "syn": True,
            "syn_ack": False,
            "ack": False,
            "last_seen": time.time()
        }
def reverse_conn(conn):
    src_ip, src_port, dst_ip, dst_port = conn
    return (dst_ip, dst_port, src_ip, src_port)

def set_synack(conn):
    if conn not in tcp_connection_tracker:
        return
    
    state = tcp_connection_tracker[conn]

    if state["syn"]:
        tcp_connection_tracker[conn]["syn_ack"] = True
        tcp_connection_tracker[conn]["last_seen"] = time.time()

def set_ack(conn):
    if conn not in tcp_connection_tracker:
        return

    state = tcp_connection_tracker[conn]

    if state["syn"] and state["syn_ack"] and not state["ack"]:
        state["ack"] = True
        tcp_connection_tracker[conn]["last_seen"] = time.time()
        print("connection established")

def is_half_open(conn):
    if conn not in tcp_connection_tracker:
        return False
    
    state = tcp_connection_tracker[conn]

    return state["syn"] and not state["ack"]

def get_half_open_tcp(src_ip):
    count = 0

    for conn in tcp_connection_tracker:
        ip = conn[0]

        if ip != src_ip:
            continue

        if is_half_open(conn):
            count += 1

    return count
    