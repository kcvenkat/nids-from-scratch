from .flood import FloodDetector
from .scan import ScanDetector

_scanner = ScanDetector()
_fl_det = Flood_Detector
DETECTORS = [_scanner.detect_port_scan, detect_flood]