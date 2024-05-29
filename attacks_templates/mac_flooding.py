from datetime import datetime, timedelta

from collections import defaultdict

from base_attack import BaseAttack



class MACFloodingDetector(BaseAttack):

    def __init__(self, reporter, config):

        super().__init__(reporter)

        self.mac_tracker = defaultdict(int)

        self.mac_threshold = config['detection_thresholds']['mac_flooding']['threshold']

        self.mac_window = timedelta(seconds=config['detection_thresholds']['mac_flooding']['window'])



    def detect(self, packet):

        if hasattr(packet, 'eth'):

            src_mac = packet.eth.src

            dst_mac = packet.eth.dst

            protocol = 'Ethernet'

            self.mac_tracker[src_mac] += 1



            if self.mac_tracker[src_mac] >= self.mac_threshold:

                first_attempt_time = datetime.now() - self.mac_window

                self.reporter.report_attack('mac_flooding', src_mac, dst_mac, protocol, {'count': self.mac_tracker[src_mac]})

                self.mac_tracker[src_mac] = 0

