from collections import defaultdict
from datetime import datetime, timedelta
from base_attack import BaseAttack

class DDOSAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.threshold = config['detection_thresholds']['ddos']['threshold']
        self.window = timedelta(seconds=config['detection_thresholds']['ddos']['window'])
        self.ip_tracker = defaultdict(list)

    def detect(self, packet):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            current_time = datetime.now()
            self.ip_tracker[src_ip].append(current_time)

            # Remove outdated timestamps
            self.ip_tracker[src_ip] = [timestamp for timestamp in self.ip_tracker[src_ip] if current_time - timestamp <= self.window]

            if len(self.ip_tracker[src_ip]) > self.threshold:
                self.reporter.report_attack('DDoS Attack', src_ip, packet.ip.dst, 'IP', {'count': len(self.ip_tracker[src_ip])})
                return True
        return False
