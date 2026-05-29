from collections import deque, defaultdict
import time
from server.alert import alert

tracker = defaultdict(lambda: {
    "ICMP": deque(),
    "TCP": deque(),
    "UDP": deque()
})

attack_state = defaultdict(lambda: {
    "ICMP": False,
    "TCP": False,
    "UDP": False
})

def get_window_count(src_ip, protocol, window):
    now = time.time()
    timestamps = tracker[src_ip][protocol]

    while timestamps and now - timestamps[0] > window:
        timestamps.popleft()

    return len(timestamps)

def track(src_ip, dst_ip, protocol, window, threshold):
    tracker[src_ip][protocol].append(time.time())
    count = get_window_count(src_ip, protocol, window)
    if count > threshold:
        if not attack_state[src_ip][protocol]:
            attack_state[src_ip][protocol] = True
            alert(src_ip, dst_ip, protocol)
            return count
    else:
        attack_state[src_ip][protocol] = False
    return None

def record_packet(src_ip, protocol):
    tracker[src_ip][protocol].append(time.time())
