# test_rule_engine.py

from client.extraction.parser import Parser
from server.event import Event
from server.utils.matcher import match_rule
from server.rule import Rule


rule_text = """
alert tcp any any -> any any (
    flags:S;
    msg:TCP SYN Test;
    
)
"""

parser = Parser(rule_text)
sid, (action, protocol, src_ip, src_port, dst_ip, dst_port), options = parser.rule_parameters()
rule = Rule(sid, action, protocol, src_ip, src_port, dst_ip, dst_port, options)

event = Event(
    timestamp=0.0,
    protocol="tcp",
    event_type="TCP:S",

    src_ip="192.168.0.129",
    dst_ip="192.168.0.1",

    src_port= "50000",
    dst_port= "80",

    flags="S"
)

print("Rule:")
print(rule)

print("\nEvent:")
print(event)

print("\nMatch:")
print(match_rule(rule, event))