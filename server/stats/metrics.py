#Functions to gather the data necessary to match with options
from server.stats.utils import get_unique_ports, get_unique_hosts, get_window_count 
def evaluate_threshold(rule, event):
    required = [
        "track",
        "threshold_type",
        "count",
        "time_frame"
    ]

    if not all(
        key in rule.options
        for key in required
    ):
        return True
    
    track = rule.options["track"]
    threshold_type = rule.options["threshold_type"]
    window = int(rule.options["time_frame"])
    count = int(rule.options["count"])

    if track == "by_dst":
        ip = event.dst_ip
    else:
        ip = event.src_ip
    
    if threshold_type == "ports":
        metric = get_unique_ports(track, ip, event.event_type, window)
    elif threshold_type == "hosts":
        metric = get_unique_hosts(track, ip, window)
    else:
        metric = get_window_count(track, ip, event.event_type, window)
    
    return metric >= count