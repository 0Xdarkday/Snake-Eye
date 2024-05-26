from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class MACFloodingDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.mac_tracker = defaultdict(list)
        self.threshold = config['threshold']
        self.window = timedelta(seconds=config['window'])

    def detect(self, packet):
        if hasattr(packet, 'eth'):
            src_mac = packet.eth.src
            now = datetime.now()
            self.mac_tracker[src_mac].append(now)

            # Remove outdated entries
            self.mac_tracker[src_mac] = [time for time in self.mac_tracker[src_mac] if now - time <= self.window]

            if len(self.mac_tracker[src_mac]) >= self.threshold:
                self.reporter.report_attack('mac_flooding', src_mac, {'occurrences': len(self.mac_tracker[src_mac])})
                self.mac_tracker[src_mac].clear()
