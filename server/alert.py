import uuid
import json
from datetime import datetime, timezone

ALERT_NAMES = {
    "ICMP:8": "ICMP Echo Request Flood",
    "TCP:S": "SYN Flood",
    "UDP": "UDP Flood",
}


def alert(src, dst, event_type, alert_type):
    print("ALERT ALERT ALERT ALERT ALERT ALERT")
    print()
    print()
    alert_name = ALERT_NAMES.get(event_type, event_type)
    alert_log = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "event_type": event_type,
        "alert_type": alert_type,
        "message": f"{alert_name} detected from {src}"
    }

    with open("alerts.json", "a") as f:
        f.write(json.dumps(alert_log) + "\n")