import uuid
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ALERT_FILE = PROJECT_ROOT / "alert.jsonl"

def alert(rule, event):
    track = rule.options.get("track", "by_src") if rule.options else "by_src"
    message = rule.options.get("msg", event.event_type) if rule.options else event.event_type

    alert_log = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "event_type": event.event_type,
        "alert_type": message,
        "msg": f"{message} targeting {event.dst_ip}" if track == "by_dst" else f"{message} detected from {event.src_ip}"
    }

    with ALERT_FILE.open("a") as f:
        f.write(json.dumps(alert_log) + "\n")