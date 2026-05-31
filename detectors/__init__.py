from .flood import detect_flood
from .scan import detect_syn_scan

DETECTORS = [detect_syn_scan, detect_flood]