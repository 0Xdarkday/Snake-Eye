from base_attack import BaseAttack

class SQLInjectionDetector(BaseAttack):
    def __init__(self, reporter, patterns):
        super().__init__(reporter)
        self.patterns = patterns

    def detect(self, packet):
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            request_uri = packet.http.request_uri
            for pattern in self.patterns:
                if pattern in request_uri:
                    self.reporter.report_attack('sql_injection', packet.ip.src, {'uri': request_uri, 'pattern': pattern})
                    break
