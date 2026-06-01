from .flood import detect_flood
from .scan import detect_port_scan

DETECTORS = [detect_port_scan, detect_flood]