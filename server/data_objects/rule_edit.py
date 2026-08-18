from server.validator import validate
from server.initiation.parser import Parser

def add_rule(rule_string):
    is_valid, error_message = validate(rule_string)
    if not is_valid:
        print(f"RULE IS NOT VALID | Error: {error_message}")
        return

    with open("rules.txt", "a") as f:
        f.write(rule_string + "\n")
    return True

def sid_lookup(sid):
    target = f"sid:{sid}"

    with open("rules.txt", "r") as f:
        for line_number, line in enumerate(f):
            normalized = line.replace(" ", "")
            if target in normalized:
                return line_number

    return -1

def edit_rule(sid, new_rule):
    is_valid, error_message = validate(new_rule)
    if not is_valid:
        print(f"RULE IS NOT VALID | Error: {error_message}")
        return
    index = sid_lookup(sid)

    if index == -1:
        return False

    with open("rules.txt", "r") as f:
        lines = f.readlines()

    lines[index] = new_rule + "\n"

    with open("rules.txt", "w") as f:
        f.writelines(lines)

    return True

def remove_rule(sid):
    index = sid_lookup(sid)

    if index == -1:
        return False

    with open("rules.txt", "r") as f:
        lines = f.readlines()

    del lines[index]

    with open("rules.txt", "w") as f:
        f.writelines(lines)

    return True

def _short(text, width):
    text = "" if text is None else str(text)
    return text if len(text) <= width else text[: width - 3] + "..."


def view_rules_table():
    rows = []

    with open("rules.txt", "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                rule = Parser(line).parse()
            except Exception:
                continue

            msg = ""
            if rule.options and "msg" in rule.options:
                msg = rule.options["msg"]

            source = f"{rule.src_ip}:{rule.src_port}"
            dest = f"{rule.dst_ip}:{rule.dst_port}"

            rows.append([
                str(rule.sid),
                str(rule.action),
                str(rule.protocol),
                source,
                dest,
                msg,
            ])

    if not rows:
        print("No rules found.")
        return

    headers = ["SID", "Action", "Proto", "Source", "Destination", "Message"]
    widths = [6, 8, 8, 24, 24, 35]

    def fmt_row(row):
        return (
            f"{_short(row[0], widths[0]):<{widths[0]}}  "
            f"{_short(row[1], widths[1]):<{widths[1]}}  "
            f"{_short(row[2], widths[2]):<{widths[2]}}  "
            f"{_short(row[3], widths[3]):<{widths[3]}}  "
            f"{_short(row[4], widths[4]):<{widths[4]}}  "
            f"{_short(row[5], widths[5]):<{widths[5]}}"
        )

    print("=" * 125)
    print(fmt_row(headers))
    print("-" * 125)

    for row in rows:
        print(fmt_row(row))

    print("=" * 125)

def view_rule_details(sid):
    index = sid_lookup(sid)

    if index == -1:
        print(f"Rule with SID {sid} not found.")
        return False

    with open("rules.txt", "r") as f:
        lines = f.readlines()

    rule = Parser(lines[index].strip()).parse()

    print("\n" + "=" * 60)
    print(f"SID:       {rule.sid}")
    print(f"Action:    {rule.action}")
    print(f"Protocol:  {rule.protocol}")

    print("\nSource")
    print(f"  IP:      {rule.src_ip}")
    print(f"  Port:    {rule.src_port}")

    print("\nDestination")
    print(f"  IP:      {rule.dst_ip}")
    print(f"  Port:    {rule.dst_port}")

    print("\nOptions")

    if rule.options:
        for key, value in rule.options.items():
            print(f"  {key:<20} {value}")
    else:
        print("  None")

    print("=" * 60 + "\n")

    return True