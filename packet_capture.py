import pyshark
import logging

def start_packet_capture(interface: str, packet_filter):
    logging.info(f"Starting packet capture on interface {interface}")
    capture = pyshark.LiveCapture(interface=interface)
    
    try:
        for packet in capture.sniff_continuously():
            packet_filter.filter(packet)
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
