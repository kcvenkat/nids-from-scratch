from server.utils.matcher import match_rule
from server.actions.alert import alert
from server.actions.log import log
from server.utils.tracker import should_alert

def perform_action(rule, event):
    if not match_rule(rule, event):
        return
    
    threshold = rule.options.get("threshold", 10) if rule.options else 10.0
    threshold = float(threshold)

    if not should_alert(rule, threshold):
        return

    if rule.action == "alert":
        alert(rule, event)

    elif rule.action == "log":
        log(rule, event)
    else:
        return
    