import logging
from colorama import Fore, Style, init  
from utils.packet_capture import start_packet_capture 
from utils.packet_filter import PacketFilter
from utils.reporter import Reporter
from utils.load import load_config

def print_logo():
    # Initialize colorama
    init(autoreset=True)

    logo = f"""
{Fore.BLUE}
/$$$$$$                      /$$                         /$$$$$$$$                    
/$$__  $$                    | $$                        | $$_____/                    
| $$  \__/ /$$$$$$$   /$$$$$$ | $$   /$$  /$$$$$$         | $$       /$$   /$$  /$$$$$$ 
|  $$$$$$ | $$__  $$ |____  $$| $$  /$$/ /$$__  $$ /$$$$$$| $$$$$   | $$  | $$ /$$__  $$
 \____  $$| $$  \ $$  /$$$$$$$| $$$$$$/ | $$$$$$$$|______/| $$__/   | $$  | $$| $$$$$$$$
 /$$  \ $$| $$  | $$ /$$__  $$| $$_  $$ | $$_____/        | $$      | $$  | $$| $$_____/
|  $$$$$$/| $$  | $$|  $$$$$$$| $$ \  $$|  $$$$$$$        | $$$$$$$$|  $$$$$$$|  $$$$$$$
 \______/ |__/  |__/ \_______/|__/  \__/ \_______/        |________/ \____  $$ \_______/
/$$                      /$$   | $$                                 /$$  | $$          
| $$                     |__/   | $$                                |  $$$$$$/          
|__/                              \__/                                 \______/

                            {Fore.BLUE}Made by Mahmoud Shaker{Style.RESET_ALL}
                            {Fore.BLUE}Welcome to Snake-Eye Network Detector\n{Style.RESET_ALL}
"""
    print(logo)
def main():
    print_logo()  

    # Load the configuration
    try:
        config = load_config('config.json')
        print("Configuration loaded successfully.")
    except Exception as e:
        print(f"Failed to load configuration: {e}")
        exit(1)

    # Set up logging based on the configuration
    try:
        logging.basicConfig(
            level=getattr(logging, config['logging']['level'].upper(), 'INFO'),
            filename=config['logging'].get('file', 'logs/reporter.log'),
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        print("Logging configured successfully.")
        logging.info("Logging configured successfully.")
    except Exception as e:
        print(f"Failed to configure logging: {e}")
        exit(1)

    # Create Reporter instance
    try:
        reporter = Reporter(
            ip=config['api_server']['ip'],
            port=config['api_server']['port'],
            report_endpoint=config['api_server']['report_endpoint'],
            use_https=config['api_server']['use_https'],
            log_file=config['logging']['file']
        )
        print("Reporter instance created successfully.")
        logging.info("Reporter instance created successfully.")
    except Exception as e:
        print(f"Failed to create Reporter instance: {e}")
        logging.error(f"Failed to create Reporter instance: {e}")
        exit(1)

    # Create PacketFilter instance
    try:
        packet_filter = PacketFilter(reporter, config)
        print("PacketFilter instance created successfully.")
    except Exception as e:
        print(f"Failed to create PacketFilter instance: {e}")
        logging.error(f"Failed to create PacketFilter instance: {e}")
        exit(1)
        
    # Start packet capture
    try:
        interface = config['interfaces']['default']
        print(f"Starting packet capture on interface {interface}")
        logging.info(f"Starting packet capture on interface {interface}")
        start_packet_capture(interface, packet_filter)
    except Exception as e:
        print(f"Failed to start packet capture: {e}")
        logging.error(f"Failed to start packet capture: {e}")
        exit(1)

if __name__ == '__main__':
    main()
