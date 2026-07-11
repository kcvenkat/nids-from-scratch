from server.utils.matcher import match_rule
from server.actions.alert import alert
from server.actions.log import log
from server.utils.tracker import should_alert

def perform_action(rule, event):
    if not match_rule(rule, event):
        return

    options = rule.options or {}
    threshold = options.get("suppress_threshold", 10)
    threshold = float(threshold)

    print(f"[DEBUG] rule_sid={rule.sid} action={rule.action} threshold={threshold} event={event.event_type} src={event.src_ip} dst={event.dst_ip}")

    if not should_alert(rule, event, threshold):
        print(f"[DEBUG] suppressing rule_sid={rule.sid} due to active suppression window")
        return

    if rule.action == "alert":
        alert(rule, event)

    elif rule.action == "log":
        log(rule, event)
    else:
        return
    