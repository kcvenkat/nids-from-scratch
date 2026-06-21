from server.detection.rule import RULE_OBJECTS
from client.extraction.parser import Parser

def load_rules():
    with open("rules.rule") as f:
        contents = f.read()
    rule_list = [
        line.strip()
        for line in contents.split("\n")
        if line.strip()
    ]

    for rule in rule_list:
        rule_obj = Parser(rule).parse()
        RULE_OBJECTS.append(rule_obj)

