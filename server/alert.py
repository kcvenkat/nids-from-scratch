import uuid
import json
from datetime import datetime, timezone

def alert(src, dst, event_type, alert_type):
    print("ALERT ALERT ALERT ALERT ALERT ALERT")
    print()
    print()
    alert_log = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "event_type": event_type,
        "alert_type": alert_type,
        "message": f"{alert_type} detected from {src}"
    }

    with open("alerts.json", "a") as f:
        f.write(json.dumps(alert_log) + "\n")