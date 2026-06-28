from pathlib import Path
from server.detection.rule import RULE_OBJECTS
from client.extraction.parser import Parser

RULE_FILE = Path(__file__).parent.parent.parent / "rules.txt"

def load_rules():
    if not RULE_FILE.exists():
        print(f"[INFO] No rule file found at {RULE_FILE}. Starting with no rules.")
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