import json
import logging
from packet_capture import start_packet_capture
from packet_filter import PacketFilter
from reporter import Reporter
from utils import load_config

def main():
    # Load configuration
    config = load_config('config.json')
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create Reporter and PacketFilter instances
    reporter = Reporter(config['api_server_ip'], config['api_server_port'], config['use_https'])
    packet_filter = PacketFilter(reporter)
    
    # Start packet capture
    start_packet_capture(config['interface'], packet_filter)

if __name__ == '__main__':
    main()
