#Functions to gather the data necessary to match with options
from detectors.utils import get_unique_ports, get_unique_hosts, get_window_count 
def evaluate_threshold(rule, event):
    track = rule.options["track"]
    threshold_type = rule.options["threshold_type"]
    window = rule.options["time_frame"]
    count = rule.options["count"]

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
    
    