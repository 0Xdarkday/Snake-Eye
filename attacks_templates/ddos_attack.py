from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack


class DDOSAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.threshold = config['detection_thresholds']['ddos']['threshold']
        self.window = config['detection_thresholds']['ddos']['window']
        self.ip_counter = defaultdict(int)

    def detect(self, packet):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            self.ip_counter[src_ip] += 1
            if self.ip_counter[src_ip] > self.threshold:
                # Check if the IP address exceeds the threshold within the window
                if self.check_threshold_exceeded(src_ip):
                    self.reporter.report_attack('ddos_attack', src_ip, packet.ip.dst, packet.transport_layer, {'count': self.ip_counter[src_ip]})
                    return True  # Attack detected
        return False  # No attack detected

    def check_threshold_exceeded(self, src_ip):
        window_start = datetime.now() - timedelta(seconds=self.window)
        for ip, count in self.ip_counter.items():
            if count >= self.threshold and ip != src_ip:
                first_attempt_time = datetime.now() - timedelta(seconds=self.window)
                if self.ip_counter[src_ip] >= self.threshold and window_start <= first_attempt_time:
                    return True
        return False
