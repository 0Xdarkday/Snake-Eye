from datetime import datetime, timedelta
from collections import defaultdict
from .base_attack import BaseAttack

class DDOSAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.ddos_tracker = defaultdict(list)
        self.ddos_threshold = config['detection_thresholds']['ddos']['threshold']
        self.ddos_window = timedelta(seconds=config['detection_thresholds']['ddos']['window'])

    def detect(self, packet):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            current_time = datetime.now()
            self.ddos_tracker[src_ip].append(current_time)

            # Remove entries outside the time window
            self.ddos_tracker[src_ip] = [time for time in self.ddos_tracker[src_ip] if current_time - time < self.ddos_window]

            if len(self.ddos_tracker[src_ip]) > self.ddos_threshold:
                self.reporter.report_attack("DDoS Atta
