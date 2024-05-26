from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack  # Use relative import

class DDOSAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.ddos_tracker = defaultdict(int)
        self.ddos_threshold = config['detection_thresholds']['ddos']['threshold']
        self.ddos_window = timedelta(seconds=config['detection_thresholds']['ddos']['window'])
        self.last_cleared = datetime.now()

    def detect(self, packet):
        now = datetime.now()
        if now - self.last_cleared > self.ddos_window:
            self.ddos_tracker.clear()
            self.last_cleared = now

        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            self.ddos_tracker[src_ip] += 1

            if self.ddos_tracker[src_ip] > self.ddos_threshold:
                self.reporter.report_attack('DDOS', src_ip, {'count': self.ddos_tracker[src_ip]})
                self.ddos_tracker[src_ip] = 0
