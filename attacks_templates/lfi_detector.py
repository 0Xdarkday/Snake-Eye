from base_attack import BaseAttack

class LFIDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.patterns = config['patterns']['lfi']

    def detect(self, packet):
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            request_uri = packet.http.request_uri
            for pattern in self.patterns:
                if pattern in request_uri:
                    self.reporter.report_attack('LFI', packet.ip.src, packet.ip.dst, 'HTTP', {'uri': request_uri, 'pattern': pattern})
                    return True
        return False
