from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack


class ARPAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.threshold = config['detection_thresholds']['arp']['threshold']
        self.window = config['detection_thresholds']['arp']['window']
        self.arp_counter = defaultdict(int)

    def detect(self, packet):
        if hasattr(packet, 'arp'):
            src_ip = packet.arp.src_proto_ipv4
            self.arp_counter[src_ip] += 1
            if self.arp_counter[src_ip] > self.threshold:
                # Check if the ARP requests exceed the threshold within the window
                if self.check_threshold_exceeded(src_ip):
                    self.reporter.report_attack('arp_flooding', src_ip, packet.arp.dst_proto_ipv4, 'ARP', {'count': self.arp_counter[src_ip]})
                    return True  # Attack detected
        return False  # No attack detected

    def check_threshold_exceeded(self, src_ip):
        window_start = datetime.now() - timedelta(seconds=self.window)
        for ip, count in self.arp_counter.items():
            if count >= self.threshold and ip != src_ip:
                first_attempt_time = datetime.now() - timedelta(seconds=self.window)
                if self.arp_counter[src_ip] >= self.threshold and window_start <= first_attempt_time:
                    return True
        return False
