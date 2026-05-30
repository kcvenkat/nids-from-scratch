from collections import deque, defaultdict
import time
from server.alert import alert

tracker = defaultdict(lambda: defaultdict(deque))
attack_state = defaultdict(lambda: defaultdict(bool))


def get_window_count(src_ip, protocol, window):
    now = time.time()
    timestamps = tracker[src_ip][protocol]

    while timestamps and now - timestamps[0] > window:
        timestamps.popleft()

    return len(timestamps)

def traffic_per_second(src_ip, event_type, window):
    if window <= 0:
        return 0

    count = get_window_count(src_ip, event_type, window)
    return count / window

def record_packet(src_ip, protocol):
    tracker[src_ip][protocol].append(time.time())