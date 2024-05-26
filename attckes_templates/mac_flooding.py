from datetime import datetime, timedelta
from collections import defaultdict
from base_attack import BaseAttack

class MACFloodingDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.mac_flooding_tracker = defaultdict(int)
        self.mac_flooding_threshold = config['detection_thresholds']['mac_flooding']['threshold']
        self.mac_flooding_window = timedelta(seconds=config['detection_thresholds']['mac_flooding']['window'])

    def detect(self, packet):
        if hasattr(packet, 'eth'):
            src_mac = packet.eth.src
            self.mac_flooding_tracker[src_mac] += 1

            if self.mac_flooding_tracker[src_mac] >= self.mac_flooding_threshold:
                first_attempt_time = datetime.now() - self.mac_flooding_window
                self.reporter.report_attack('mac_flooding', src_mac, {'count': self.mac_flooding_tracker[src_mac]})
                self.mac_flooding_tracker[src_mac] = 0
