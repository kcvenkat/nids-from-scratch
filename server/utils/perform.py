from server.utils.matcher import match_rule
from server.actions.alert import alert
from server.actions.log import log

def perform_action(rule, event):

    if not match_rule(rule, event):
        return

    if rule.action == "alert":
        alert(rule, event)

    elif rule.action == "log":
        log(rule, event)
    else:
        return
    