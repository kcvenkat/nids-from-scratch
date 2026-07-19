from server.detection.tracker import get_unique_ports, get_unique_hosts, get_window_count

def evaluate_threshold(rule, event):
    track = rule.options.get("track", "by_src")
    threshold_type = rule.options.get("threshold_type", "count")
    window = int(rule.options.get("time_frame", 30))
    count = int(rule.options.get("count", 25))

    if track == "by_dst":
        ip, counterpart_ip = event.dst_ip, event.src_ip
    else:
        ip, counterpart_ip = event.src_ip, event.dst_ip
    
    if threshold_type == "ports":
        metric = get_unique_ports(track, ip, counterpart_ip, event.event_type, window)
    elif threshold_type == "hosts":
        metric = get_unique_hosts(track, ip, window)
    else:
        metric = get_window_count(track, ip, event.event_type, window)
    
    return metric >= count