#TODO: rename and move into utils folder

from collections import deque, defaultdict
import time
from server.detection.rule import RULE_OBJECTS

tracker = {
    "by_src": defaultdict(lambda: defaultdict(deque)),
    "by_dst": defaultdict(lambda: defaultdict(deque))
}
port_tracker = {
    "by_src": defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(deque)))),
    "by_dst": defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(deque))))
}
host_tracker = {
    "by_src": defaultdict(dict),
    "by_dst": defaultdict(dict)
}
tcp_connection_tracker = {}
attack_state = {}

def get_window_count(track, ip, event_type, window):
    now = time.time()
    return sum(1 for ts in tracker[track][ip][event_type] if now - ts <= window)

def get_unique_ports(track, src_ip, dst_ip, event_type, window):
    now = time.time()
    return sum(
        1 for timestamps in port_tracker[track][src_ip][dst_ip][event_type].values()
        if any(now - ts <= window for ts in timestamps)
    )

def get_unique_hosts(track, ip, window):
    now = time.time()
    return sum(1 for last_seen in host_tracker[track][ip].values() if now - last_seen <=window)

def record_packet(src_ip, dst_ip, event_type):
    tracker["by_src"][src_ip][event_type].append(time.time())
    tracker["by_dst"][dst_ip][event_type].append(time.time())

def record_port(src_ip, dst_ip, dst_port, event_type):
    port_tracker["by_src"][src_ip][dst_ip][event_type][dst_port].append(time.time())
    port_tracker["by_dst"][dst_ip][src_ip][event_type][dst_port].append(time.time())

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

def session_exists(conn):
    return get_conn_state(conn) is not None

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

def build_attack_state_key(rule, event):
    return tuple([rule.sid, event.protocol, event.src_ip, event.dst_ip])


def log_attack_state(rule, event):
    connection_key = build_attack_state_key(rule, event)
    attack_state[connection_key] = time.time()


def should_alert(rule, event, threshold=10.0):
    now = time.time()
    connection_key = build_attack_state_key(rule, event)
    has_state = connection_key in attack_state
    last_seen = attack_state.get(connection_key)

    print(
        f"[DEBUG] rule_sid={rule.sid} packet_eval active_state={has_state} "
        f"key={connection_key} last_seen={last_seen if last_seen is not None else 'None'} threshold={threshold}s"
    )

    if not has_state:
        log_attack_state(rule, event)
        print(f"[DEBUG] rule_sid={rule.sid} first alert; allowing")
        return True

    elapsed = now - attack_state[connection_key]
    print(f"[DEBUG] rule_sid={rule.sid} elapsed={elapsed:.3f}s threshold={threshold}s")

    if elapsed >= threshold:
        attack_state.pop(connection_key)
        print(f"[DEBUG] rule_sid={rule.sid} threshold expired; allowing new alert")
        return True

    return False
        
