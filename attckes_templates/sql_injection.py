from .base_attack import BaseAttack

class SQLInjectionDetector(BaseAttack):
    def __init__(self, reporter, config):
        super().__init__(reporter)
        self.sql_injection_patterns = config['patterns']['sql_injection']

    def detect(self, packet):
        if hasattr(packet, 'http'):
            http_payload = packet.http.file_data.lower()
            for signature in self.sql_injection_patterns:
                if signature in http_payload:
                    self.reporter.report_attack("SQL Injection", packet.ip.src, http_payload)
                    break

