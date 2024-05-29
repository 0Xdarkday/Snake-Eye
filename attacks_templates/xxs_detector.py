from base_attack import BaseAttack

class XXSDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.xxs_patterns = config['patterns']['xxs']

    def detect(self, packet):
        if hasattr(packet, 'http'):
            http_payload = getattr(packet.http, 'file_data', '')
            for pattern in self.xxs_patterns:
                if pattern in http_payload:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.transport_layer
                    self.reporter.report_attack('XXS', src_ip, dst_ip, protocol, {'payload': http_payload})
                    break
