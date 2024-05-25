import json
import base64
import requests
import logging

class Reporter:
    def __init__(self, ip: str, port: str, use_https: bool = False):
        self.ip = ip
        self.port = port
        self.protocol = 'https' if use_https else 'http'

    def report(self, message: dict):
        temp = json.dumps(message)
        jsonString = temp.encode('ascii')
        b64 = base64.b64encode(jsonString)
        jsonPayload = b64.decode('utf8').replace("'", '"')
        logging.info(f"Reporting packet: {jsonPayload}")

        try:
            url = f'{self.protocol}://{self.ip}:{self.port}/api/?{jsonPayload}'
            response = requests.get(url)
            response.raise_for_status()
        except requests.RequestException as e:
            logging.error(f"Error reporting packet: {e}")
