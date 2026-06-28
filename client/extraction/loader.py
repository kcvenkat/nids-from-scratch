from pathlib import Path
from server.detection.rule import RULE_OBJECTS
from client.extraction.parser import Parser

RULE_FILE = Path(__file__).parent.parent.parent / "rules.txt"

def load_rules():
    print(f"Looking for rules at: {RULE_FILE}")
    if not RULE_FILE.exists():
        print(f"[INFO] No rule file found at {RULE_FILE}. Starting with no rules.")
        return

    with RULE_FILE.open() as f:
        contents = f.read()

    print("Contents:")
    print(contents)

    rule_list = [
        line.strip()
        for line in contents.split("\n")
        if line.strip()
    ]

    print(f"Found {len(rule_list)} rules")

    for rule in rule_list:
        print(f"Parsing rule: {rule}")
        rule_obj = Parser(rule).parse()
        RULE_OBJECTS.append(rule_obj)
    
    print(f"Loaded {len(RULE_OBJECTS)} rules")