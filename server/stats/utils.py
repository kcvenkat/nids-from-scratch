#TODO: rename and move into utils folder

from collections import deque, defaultdict
import time
from server.detection.rule import RULE_OBJECTS

tracker = {
    "by_src": defaultdict(lambda: defaultdict(deque)),
    "by_dst": defaultdict(lambda: defaultdict(deque))
}
port_tracker = {
    "by_src": defaultdict(lambda: defaultdict(lambda: defaultdict(deque))),
    "by_dst": defaultdict(lambda: defaultdict(lambda: defaultdict(deque)))
}
host_tracker = {
    "by_src": defaultdict(dict),
    "by_dst": defaultdict(dict)
}
tcp_connection_tracker = {}

def get_window_count(track, ip, event_type, window):
    now = time.time()
    return sum(1 for ts in tracker[track][ip][event_type] if now - ts <= window)

#unique ports overall
def get_unique_ports(track, ip, event_type, window):
    now = time.time()
    return sum(1 for timestamps in port_tracker [track][ip][event_type].values() if any(now - ts <= window for ts in timestamps))

def get_unique_hosts(track, ip, window):
    now = time.time()
    return sum(1 for last_seen in host_tracker[track][ip].values() if now - last_seen <=window)

def record_packet(src_ip, dst_ip, event_type):
    tracker["by_src"][src_ip][event_type].append(time.time())
    tracker["by_dst"][dst_ip][event_type].append(time.time())

def record_port(src_ip, dst_ip, dst_port, event_type):
    port_tracker["by_src"][src_ip][event_type][dst_port].append(time.time())
    port_tracker["by_dst"][dst_ip][event_type][dst_port].append(time.time())

def record_unique_host(src_ip, dst_ip):
    now = time.time()

    host_tracker["by_src"][src_ip][dst_ip] = now
    host_tracker["by_dst"][dst_ip][src_ip] = now

def record_tcp(src_ip, src_port, dst_ip, dst_port):
    conn = (src_ip, src_port, dst_ip, dst_port)

    if conn not in tcp_connection_tracker:
        tcp_connection_tracker[conn] = {
            "client": src_ip,
            "cport": src_port,

            "server": dst_ip,
            "sport": dst_port,

            "syn": True,
            "syn_ack": False,
            "ack": False,
            "last_seen": time.time()
        }

def reverse_conn(conn):
    src_ip, src_port, dst_ip, dst_port = conn
    return (dst_ip, dst_port, src_ip, src_port)

def get_conn_state(conn):
    if conn in tcp_connection_tracker:
        return tcp_connection_tracker[conn]
    
    reverse = reverse_conn(conn)

    if reverse in tcp_connection_tracker:
        return tcp_connection_tracker[reverse]
    
    return None

def set_synack(conn):
    state = get_conn_state(conn)

    if state is None:
        return

    if state["syn"]:
        state["syn_ack"] = True
        state["last_seen"] = time.time()

def set_ack(conn):
    state = get_conn_state(conn)

    if state is None:
        return

    if state["syn"] and state["syn_ack"] and not state["ack"]:
        state["ack"] = True
        state["last_seen"] = time.time()

def is_half_open(conn):
    state = get_conn_state(conn)

    if state is None:
        return False
    
    return state["syn"] and not state["ack"]

def is_established(conn):
    state = get_conn_state(conn)

    if state is None:
        return False

    return state["syn"] and state["syn_ack"] and state["ack"]

def get_client(conn):
    state = get_conn_state(conn)

    return state["client"] if state else None

def get_server(conn):
    state = get_conn_state(conn)

    return state["server"] if state else None

def is_to_client(conn, event):
    state = get_conn_state(conn)

    if state is None:
        return False

    return (event.src_ip == state["server"] and event.dst_ip == state["client"])

def is_to_server(conn, event):
    state = get_conn_state(conn)

    if state is None:
        return False

    return (event.src_ip == state["client"] and event.dst_ip == state["server"])

def get_half_open_tcp(track, ip):
    count = 0

    for conn in tcp_connection_tracker:
        if track == "by_dst":
            conn_ip = conn[2]
        else:
            conn_ip = conn[0] 
        if conn_ip != ip:
            continue

        if is_half_open(conn):
            count += 1

    return count
    
def get_available_sid():
    highest_sid = 0
    for rule in RULE_OBJECTS:
        if highest_sid < rule.sid:
            highest_sid = rule.sid
    
    return highest_sid + 1


def make_flow_key(event):
    if event.src_ip is None or event.dst_ip is None or event.protocol.lower() is None:
        return None
    if event.src_port is None or event.dst_port is None:
        return (event.src_ip, None, event.dst_ip, None, event.protocol.lower())

    return (event.src_ip, event.src_port, event.dst_ip, event.dst_port, event.protocol.lower())

