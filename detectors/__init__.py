from .flood import FloodDetector
from .scan import ScanDetector

_scanner = ScanDetector()
_fldet = FloodDetector()
DETECTORS = [_scanner.detect_port_scan, _fldet.detect_flood]