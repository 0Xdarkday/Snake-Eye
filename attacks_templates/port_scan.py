from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack


class PortScanDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.threshold = config['detection_thresholds']['port_scan']['threshold']
        self.window = config['detection_thresholds']['port_scan']['window']
        self.port_counter = defaultdict(int)

    def detect(self, packet):
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            src_ip = packet.ip.src
            dst_port = packet.tcp.dstport
            self.port_counter[(src_ip, dst_port)] += 1
            if self.port_counter[(src_ip, dst_port)] > self.threshold:
                # Check if the port exceeds the threshold within the window
                if self.check_threshold_exceeded(src_ip, dst_port):
                    self.reporter.report_attack('port_scan', src_ip, packet.ip.dst, 'TCP', {'dst_port': dst_port})
                    return True  # Attack detected
        return False  # No attack detected

    def check_threshold_exceeded(self, src_ip, dst_port):
        window_start = datetime.now() - timedelta(seconds=self.window)
        for (ip, port), count in self.port_counter.items():
            if count >= self.threshold and ip == src_ip and port == dst_port:
                first_attempt_time = datetime.now() - timedelta(seconds=self.window)
                if self.port_counter[(src_ip, dst_port)] >= self.threshold and window_start <= first_attempt_time:
                    return True
        return False
