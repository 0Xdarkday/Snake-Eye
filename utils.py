import json
import logging

def load_config(config_file: str) -> dict:
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
            return config
    except FileNotFoundError:
        logging.error(f"Config file {config_file} not found.")
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {config_file}.")
