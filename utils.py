import json
import logging

def load_config(config_file: str) -> dict:
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
            validate_config(config)
            return config
    except FileNotFoundError:
        logging.error(f"Config file {config_file} not found.")
        raise
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {config_file}.")
        raise

def validate_config(config: dict):
    required_keys = ['api_server', 'logging', 'detection_thresholds', 'patterns', 'interfaces']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")
