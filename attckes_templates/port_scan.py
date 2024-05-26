from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack  # Use relative import

class PortScanDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.port_scan_tracker = defaultdict(lambda: defaultdict(int))
        self.port_scan_threshold = config['detection_thresholds']['port_scan']['threshold']
        self.port_scan_window = timedelta(seconds=config['detection_thresholds']['port_scan']['window'])

    def detect(self, packet):
        if packet.transport_layer == 'TCP' and hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_port = packet.tcp.dstport
            self.port_scan_tracker[src_ip][dst_port] += 1

            if len(self.port_scan_tracker[src_ip]) >= self.port_scan_threshold:
                first_attempt_time = min(self.port_scan_tracker[src_ip], key=self.port_scan_tracker[src_ip].get)
                if datetime.now() - first_attempt_time > self.port_scan_window:
                    self.reporter.report_attack('Port Scan', src_ip, self.port_scan_tracker[src_ip])
                    self.port_scan_tracker[src_ip].clear()
