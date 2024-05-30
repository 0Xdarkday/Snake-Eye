from collections import defaultdict
from datetime import datetime, timedelta

class ICMPPingDetector:
    def __init__(self, reporter, config):
        self.reporter = reporter
        self.threshold = config['detection_thresholds']['icmp']['threshold']
        self.window = timedelta(seconds=config['detection_thresholds']['icmp']['window'])
        self.icmp_tracker = defaultdict(list)

    def detect(self, packet):
        if hasattr(packet, 'icmp'):
            src_ip = packet.ip.src
            current_time = datetime.now()

            self.icmp_tracker[src_ip].append(current_time)

            # Remove outdated timestamps
            self.icmp_tracker[src_ip] = [timestamp for timestamp in self.icmp_tracker[src_ip] if current_time - timestamp <= self.window]

            if len(self.icmp_tracker[src_ip]) > self.threshold:
                self.reporter.report_attack('ICMP Ping Flood', src_ip, packet.ip.dst, 'ICMP', {'count': len(self.icmp_tracker[src_ip])})
                return True
        return False


