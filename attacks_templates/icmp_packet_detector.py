from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class ICMPPingDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.icmp_threshold = config['detection_thresholds']['icmp']['threshold']
        self.icmp_window = config['detection_thresholds']['icmp']['window']
        self.icmp_tracker = {}

    def detect(self, packet):
        if hasattr(packet, 'icmp'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'ICMP'
            timestamp = packet.sniff_timestamp

            current_count = self.icmp_tracker.get(src_ip, 0)
            self.icmp_tracker[src_ip] = current_count + 1

            if self.icmp_tracker[src_ip] > self.icmp_threshold:
                # Check if the ICMP packets exceed the threshold within the window
                if self.check_threshold_exceeded(src_ip):
                    self.reporter.report_attack('icmp_ping', src_ip, {
                        'dst_ip': dst_ip,
                        'protocol': protocol,
                        'count': self.icmp_tracker[src_ip],
                        'timestamp': timestamp
                    })
                    return True  # Attack detected

        return False  # No attack detected

    def check_threshold_exceeded(self, src_ip):
        window_start = datetime.now() - timedelta(seconds=self.icmp_window)
        for ip, count in self.icmp_tracker.items():
            if count >= self.icmp_threshold and ip != src_ip:
                first_attempt_time = datetime.now() - timedelta(seconds=self.icmp_window)
                if self.icmp_tracker[src_ip] >= self.icmp_threshold and window_start <= first_attempt_time:
                    return True
        return False
