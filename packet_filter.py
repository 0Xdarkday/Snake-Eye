from collections import defaultdict
import ipaddress
from pyshark.packet.packet import Packet
from reporter import Reporter
from attacks.port_scan import PortScanDetector
from attacks.ddos_attack import DDOSAttackDetector
from attacks.sql_injection import SQLInjectionDetector
from attacks.mac_flooding import MACFloodingDetector
from attacks.arp_attack import ARPAttackDetector

class PacketFilter:
    def __init__(self, reporter: Reporter, config):
        self.reporter = reporter
        self.config = config
        self.detectors = [
            PortScanDetector(reporter, config['detection_thresholds']['port_scan']),
            DDOSAttackDetector(reporter, config['detection_thresholds']['ddos']),
            SQLInjectionDetector(reporter, config['patterns']['sql_injection']),
            MACFloodingDetector(reporter, config['detection_thresholds']['mac_flooding']),
            ARPAttackDetector(reporter, config['detection_thresholds']['arp'])
        ]

    def is_private_ip(self, ip_address: str) -> bool:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private

    def is_api_server(self, packet: Packet) -> bool:
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            if ((packet.ip.src == self.reporter.ip) or (packet.ip.dst == self.reporter.ip)) and \
               ((packet.tcp.dstport == self.reporter.port) or (packet.tcp.srcport == self.reporter.port)):
                return True
        return False

    def filter(self, packet: Packet):
        if self.is_api_server(packet):
            return

        if hasattr(packet, 'icmp'):
            self._report_packet(packet)
            return

        if packet.transport_layer in ['TCP', 'UDP']:
            if hasattr(packet, 'ip'):
                if self.is_private_ip(packet.ip.src) and self.is_private_ip(packet.ip.dst):
                    self._report_packet(packet)

        for detector in self.detectors:
            detector.detect(packet)

    def _report_packet(self, packet: Packet):
        p = {
            'ipSrc': packet.ip.src,
            'ipDst': packet.ip.dst,
            'sniff_timestamp': packet.sniff_timestamp,
            'highest_layer': packet.highest_layer,
            'layer': packet.transport_layer,
            'srcPort': getattr(packet[packet.transport_layer.lower()], 'srcport', ''),
            'dstPort': getattr(packet[packet.transport_layer.lower()], 'dstport', '')
        }
        self.reporter.report(p)
