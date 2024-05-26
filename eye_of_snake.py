import logging
from packet_capture import start_packet_capture
from packet_filter import PacketFilter
from reporter import Reporter
from utils import load_config

def main():
    # Load configuration
    config = load_config('config.json')
    
    # Setup logging
    logging.basicConfig(level=getattr(logging, config['logging']['level'].upper(), 'INFO'), format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Initialize Reporter
    reporter = Reporter(
        config['api_server']['ip'], 
        config['api_server']['port'], 
        config['api_server']['base_url'], 
        config['api_server']['report_endpoint'],
        config['api_server']['use_https'],
        config['logging']['file']
    )

    # Initialize PacketFilter
    packet_filter = PacketFilter(reporter, config)
    
    # Start packet capture
    start_packet_capture(config['interfaces']['default'], packet_filter)

    # Generate HTML report
    reporter.generate_html_report('network_security_report.html')

if __name__ == '__main__':
    main()
