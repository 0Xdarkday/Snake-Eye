from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class ARPAttackDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.arp_tracker = defaultdict(list)
        self.threshold = config['threshold']
        self.window = timedelta(seconds=config['window'])

    def detect(self, packet):
        if hasattr(packet, 'arp'):
            src_ip = packet.arp.src_proto_ipv4
            now = datetime.now()
            self.arp_tracker[src_ip].append(now)

            # Remove outdated entries
            self.arp_tracker[src_ip] = [time for time in self.arp_tracker[src_ip] if now - time <= self.window]

            if len(self.arp_tracker[src_ip]) >= self.threshold:
                self.reporter.report_attack('arp_attack', src_ip, {'occurrences': len(self.arp_tracker[src_ip])})
                self.arp_tracker[src_ip].clear()
