from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class DDOSAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.ddos_tracker = defaultdict(list)
        self.threshold = config['threshold']
        self.window = timedelta(seconds=config['window'])

    def detect(self, packet):
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            now = datetime.now()
            self.ddos_tracker[src_ip].append(now)

            # Remove outdated entries
            self.ddos_tracker[src_ip] = [time for time in self.ddos_tracker[src_ip] if now - time <= self.window]
            
            if len(self.ddos_tracker[src_ip]) >= self.threshold:
                self.reporter.report_attack('ddos', src_ip, {'occurrences': len(self.ddos_tracker[src_ip])})
                self.ddos_tracker[src_ip].clear()
