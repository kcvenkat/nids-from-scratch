import ipaddress

from server.initiation.parser import Parser


def validate(rule_string):
    try:
        rule = Parser(rule_string).parse()
    except Exception as e:
        return False, f"Parse error: {e}"

    if rule.action not in ("alert", "log"):
        return False, "Invalid action."

    if rule.protocol not in ("tcp", "udp", "icmp", "arp", "any"):
        return False, "Invalid protocol."

    for ip in (rule.src_ip, rule.dst_ip):
        if ip.lower() != "any":
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return False, f"Invalid IP address: {ip}"

    for port in (rule.src_port, rule.dst_port):
        if str(port).lower() != "any":
            if not str(port).isdigit():
                return False, f"Invalid port: {port}"

            if not (0 <= int(port) <= 65535):
                return False, f"Port out of range: {port}"

    options = rule.options or {}

    if "sid" not in options:
        return False, "Rule must include a sid."

    try:
        int(options["sid"])
    except ValueError:
        return False, "sid must be an integer."
    
    allowed = {
        "msg",
        "flags",
        "icmp_type",
        "arp_op",
        "flow",
        "track",
        "threshold_type",
        "count",
        "time_frame",
        "sid",
        "suppress_threshold"
    }

    for key in options:
        if key not in allowed:
            return False, f"Unknown option '{key}'."

    if "flags" in options:
        if rule.protocol != "tcp":
            return False, "flags may only be used with TCP."

        valid_flags = set("FSRPAUEC")
        if any(flag not in valid_flags for flag in options["flags"]):
            return False, "Invalid TCP flag."

    if "icmp_type" in options:
        if rule.protocol != "icmp":
            return False, "icmp_type only applies to ICMP."

        if not options["icmp_type"].isdigit():
            return False, "icmp_type must be an integer."

    if "arp_op" in options:
        if rule.protocol != "arp":
            return False, "arp_op only applies to ARP."

        if not options["arp_op"].isdigit():
            return False, "arp_op must be an integer."

    if "flow" in options:
        if options["flow"] not in (
            "stateless",
            "established",
            "half_open",
            "to_server",
            "to_client",
        ):
            return False, "Invalid flow option."

    if "track" in options:
        if options["track"] not in ("by_src", "by_dst"):
            return False, "track must be by_src or by_dst."

    if "threshold_type" in options:
        if options["threshold_type"] not in ("count", "ports", "hosts"):
            return False, "Invalid threshold_type."

        if "count" not in options:
            return False, "threshold_type requires count."

        if "time_frame" not in options:
            return False, "threshold_type requires time_frame."

    for field in ("count", "time_frame", "threshold"):
        if field in options:
            if not options[field].isdigit():
                return False, f"{field} must be an integer."

    return True, None