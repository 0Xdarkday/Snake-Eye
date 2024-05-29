import logging
import ipaddress
from pyshark.packet.packet import Packet
from utils.reporter import Reporter
from attacks_templates import (
    PortScanDetector, DDOSAttackDetector, SQLInjectionDetector,
    MACFloodingDetector, ARPAttackDetector, ICMPPingDetector,
    XXSDetector, SSTIDetector, CSRFDetector, CRLFDetector
)

class PacketFilter:
    def __init__(self, reporter: Reporter, config):
        self.reporter = reporter
        self.config = config
        self.detectors = [
            PortScanDetector(reporter, config),
            DDOSAttackDetector(reporter, config),
            SQLInjectionDetector(reporter, config),
            MACFloodingDetector(reporter, config),
            ICMPPingDetector(reporter, config),
            ARPAttackDetector(reporter, config),
            XXSDetector(reporter, config),
            SSTIDetector(reporter, config),
            CSRFDetector(reporter, config),
            CRLFDetector(reporter, config)
        ]

    def is_private_ip(self, ip_address: str) -> bool:
        """Check if the IP address is private."""
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private

    def is_api_server(self, packet: Packet) -> bool:
        """Check if the packet is directed to the API server."""
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            if ((packet.ip.src == self.reporter.ip) or (packet.ip.dst == self.reporter.ip)) and \
               ((packet.tcp.dstport == self.reporter.port) or (packet.tcp.srcport == self.reporter.port)):
                return True
        return False

    def filter(self, packet: Packet):
        """Filter the packet and process it through various detectors."""
        if self.is_api_server(packet):
            # Skip packets directed to the API server to avoid false positives.
            return

        # Process packet through all detectors
        for detector in self.detectors:
            try:
                if detector.detect(packet):
                    # If a detector identifies a suspicious packet, report it
                    self.report_packet(packet)
            except Exception as e:
                # Log any exception that occurs in a detector
                logging.error(f"Error in detector {detector.__class__.__name__}: {e}")

    def report_packet(self, packet: Packet):
        """Report a suspicious packet."""
        if hasattr(packet, 'ip'):
            report_data = {
                'ipSrc': packet.ip.src,
                'ipDst': packet.ip.dst,
                'sniff_timestamp': packet.sniff_timestamp,
                'highest_layer': packet.highest_layer,
                'layer': packet.transport_layer,
                'srcPort': getattr(packet[packet.transport_layer.lower()], 'srcport', ''),
                'dstPort': getattr(packet[packet.transport_layer.lower()], 'dstport', '')
            }
            self.reporter.report(report_data)
