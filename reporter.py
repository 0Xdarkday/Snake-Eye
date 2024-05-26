import json
import base64
import requests
import logging

class Reporter:
    def __init__(self, ip, port, report_endpoint='report.php', use_https=False, log_file='logs/reporter.log'):
        self.ip = ip
        self.port = port
        self.protocol = 'https' if use_https else 'http'
        self.report_endpoint = report_endpoint
        self.reports = []  # Store reports
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Set up logging
        logging.basicConfig(level=logging.INFO, filename=log_file, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def report(self, message):
        try:
            json_payload = base64.b64encode(json.dumps(message).encode('ascii')).decode('utf8')
            self.logger.info(f"Reporting packet: {json_payload}")
            url = f'{self.protocol}://{self.ip}:{self.port}/{self.report_endpoint}'
            response = requests.post(url, data=json_payload)
            response.raise_for_status()
            self.logger.info(f"Report sent successfully: {response.text}")
        except requests.RequestException as e:
            self.logger.exception(f"Error while sending report: {e}")

    def report_attack(self, attack_type, src_ip, details):
        report_data = {
            'attack_type': attack_type,
            'src_ip': src_ip,
            'details': details
        }
        self.logger.info(f"Reporting attack: {attack_type} from {src_ip}")
        self.report(report_data)
