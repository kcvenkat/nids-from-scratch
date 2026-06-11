#Methods to detect if a rule matches a packet
def matches_sid(rule, event):
    return rule.sid == event.sid
    
def matches_protocol(rule, event):
    return rule.protocol.lower() == event.protocol.lower()

def matches_src_ip(rule, event):
    return rule.src_ip == event.src_ip

def matches_dst_ip(rule, event):
    return rule.dst_ip == event.dst_ip

def matches_src_port(rule, event):
    return rule.src_port == event.src_port

def matches_dst_port(rule, event):
    return rule.dst_port == event.dst_port
