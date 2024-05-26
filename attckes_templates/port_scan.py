from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class PortScanDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.port_scan_tracker = defaultdict(lambda: defaultdict(list))
        self.threshold = config['threshold']
        self.window = timedelta(seconds=config['window'])

    def detect(self, packet):
        if packet.transport_layer == 'TCP' and hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_port = packet.tcp.dstport
            now = datetime.now()
            self.port_scan_tracker[src_ip][dst_port].append(now)

            # Remove outdated entries
            for port in list(self.port_scan_tracker[src_ip].keys()):
                self.port_scan_tracker[src_ip][port] = [time for time in self.port_scan_tracker[src_ip][port] if now - time <= self.window]
                if not self.port_scan_tracker[src_ip][port]:
                    del self.port_scan_tracker[src_ip][port]

            if len(self.port_scan_tracker[src_ip]) >= self.threshold:
                self.reporter.report_attack('port_scan', src_ip, self.port_scan_tracker[src_ip])
                self.port_scan_tracker[src_ip].clear()
