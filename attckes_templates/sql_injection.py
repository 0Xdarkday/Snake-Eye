from base_attack import BaseAttack  # Use relative import

class SQLInjectionDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.patterns = config['patterns']['sql_injection']

    def detect(self, packet):
        if hasattr(packet, 'http') and hasattr(packet.http, 'request_uri'):
            request_uri = packet.http.request_uri
            for pattern in self.patterns:
                if pattern in request_uri:
                    self.reporter.report_attack('SQL Injection', packet.ip.src, {'uri': request_uri, 'pattern': pattern})
                    break
