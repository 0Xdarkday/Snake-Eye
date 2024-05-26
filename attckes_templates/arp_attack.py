from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class ARPAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.arp_tracker = defaultdict(int)
        self.arp_threshold = config['detection_thresholds']['arp']['threshold']
        self.arp_window = timedelta(seconds=config['detection_thresholds']['arp']['window'])

    def detect(self, packet):
        if hasattr(packet, 'arp'):
            src_ip = packet.arp.src_proto_ipv4
            self.arp_tracker[src_ip] += 1

            if self.arp_tracker[src_ip] >= self.arp_threshold:
                first_attempt_time = datetime.now() - self.arp_window
                self.reporter.report_attack('arp', src_ip, {'count': self.arp_tracker[src_ip]})
                self.arp_tracker[src_ip] = 0
