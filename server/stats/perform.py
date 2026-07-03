from server.stats.matcher import match_rule
from server.actions.alert import alert
from server.actions.log import log
from server.stats.flow import should_emit_alert


def perform_action(rule, event):

    if not match_rule(rule, event):
        return

    if rule.action == "alert":
        if should_emit_alert(rule, event):
            alert(rule, event)
        return

    if rule.action == "log":
        if should_emit_alert(rule, event):
            log(rule, event)
        return

    return
    