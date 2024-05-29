from base_attack import BaseAttack

class CRLFDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.crlf_patterns = config['patterns']['crlf']

    def detect(self, packet):
        if hasattr(packet, 'http'):
            http_payload = getattr(packet.http, 'file_data', '')
            for pattern in self.crlf_patterns:
                if pattern in http_payload:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.transport_layer
                    self.reporter.report_attack('CRLF', src_ip, dst_ip, protocol, {'payload': http_payload})
                    break
