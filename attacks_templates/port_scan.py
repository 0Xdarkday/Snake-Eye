from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class PortScanDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.threshold = config['detection_thresholds']['port_scan']['threshold']
        self.window = timedelta(seconds=config['detection_thresholds']['port_scan']['window'])
        self.special_threshold = config['detection_thresholds']['port_scan'].get('special_threshold', 1000)
        self.special_window = timedelta(seconds=config['detection_thresholds']['port_scan'].get('special_window', 10))
        self.ip_tracker = defaultdict(lambda: defaultdict(list))

    def detect(self, packet):
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            src_ip = packet.ip.src
            dst_port = packet.tcp.dstport
            current_time = datetime.now()
            self.ip_tracker[src_ip][dst_port].append(current_time)

            # Remove outdated timestamps
            self.ip_tracker[src_ip][dst_port] = [timestamp for timestamp in self.ip_tracker[src_ip][dst_port] if current_time - timestamp <= self.window]

            # Normal ports
            if dst_port not in [443, 53]:
                if len(self.ip_tracker[src_ip][dst_port]) > self.threshold:
                    self.reporter.report_attack('Port Scanning', src_ip, packet.ip.dst, 'TCP', {'port': dst_port, 'count': len(self.ip_tracker[src_ip][dst_port])})
                    return True
            else:
                # Special handling for ports 443 and 53
                self.ip_tracker[src_ip][dst_port] = [timestamp for timestamp in self.ip_tracker[src_ip][dst_port] if current_time - timestamp <= self.special_window]
                if len(self.ip_tracker[src_ip][dst_port]) > self.special_threshold:
                    self.reporter.report_attack('Potential DDoS on Port 443/53', src_ip, packet.ip.dst, 'TCP', {'port': dst_port, 'count': len(self.ip_tracker[src_ip][dst_port])})
                    return True
        return False
