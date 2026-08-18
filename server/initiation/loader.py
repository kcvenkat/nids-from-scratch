from pathlib import Path
from server.data_objects.rule import RULE_OBJECTS
from server.initiation.parser import Parser

RULE_FILE = Path(__file__).resolve().parent.parent / "rules.txt"


def load_rules():
    if not RULE_FILE.exists():
        return

    with RULE_FILE.open() as f:
        contents = f.read()

    rule_list = [
        line.strip()
        for line in contents.split("\n")
        if line.strip()
    ]

    for rule in rule_list:
        rule_obj = Parser(rule).parse()
        RULE_OBJECTS.append(rule_obj)