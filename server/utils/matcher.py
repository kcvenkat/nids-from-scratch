from detectors.utils import is_established, is_half_open, is_to_client, is_to_server
#Functions to detect if a rule matches a packet  
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

def matches_base(rule, event):
    return all([
        matches_protocol(rule, event),
        matches_src_ip(rule, event),
        matches_dst_ip(rule, event),
        matches_src_port(rule, event),
        matches_dst_port(rule, event)
    ])
  
def matches_flags(rule, event):
    return rule.flags == event.flags

def matches_icmp_type(rule, event):
    return rule.icmp_type == event.icmp_type

def matches_arp_op(rule, event):
    return rule.arp_op == event.arp_op

def matches_flow(rule, event):
    if "flow" not in rule.options:
        return True
    
    flow = rule.options["flow"]

    conn = event.conn

    if conn is None:
        return False
    
    if flow == "stateless":
        return True
    if flow == "established":
        return is_established(conn)
    elif flow == "half_open":
        return is_half_open(conn)
    elif flow == "to_server":
        return is_to_server(conn, event)
    elif flow == "to_client":
        return is_to_client(conn, event)
    
    return False

def matches_options(rule, event):
    if "flags" in rule.options:
        if not matches_flags(rule, event):
            return False
    if "icmp_type" in rule.options:
        if not matches_icmp_type(rule, event):
            return False
    if "arp_op" in rule.options:
        if not matches_arp_op(rule, event):
            return False
    
    return True

def match_rule(rule, event):
    if not matches_base(rule, event):
        return False
    if rule.options:
        if not matches_options(rule, event):
            return False
    # if not evaluate_threshold(rule, event):
    #     return False
    
    return True

