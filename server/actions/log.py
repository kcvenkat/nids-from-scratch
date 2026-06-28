import uuid
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
LOG_FILE = PROJECT_ROOT / "log.json"

def log(rule, event):
    event_log = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "event_type": event.event_type,
        "log_msg": rule.msg,
         "msg": f"{rule.msg} targeting {event.dst_ip}" if rule.options["track"] == "by_dst" else f"{rule.msg} detected from {event.src_ip}"
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event_log) + "\n")