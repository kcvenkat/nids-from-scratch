from .flood import FloodDetector
from .scan import PortScanDetector, HostScanDetector

_port = PortScanDetector()
_host = HostScanDetector()
_fldet = FloodDetector()
DETECTORS = [_port.detect, _host.detect, _fldet.detect_flood]