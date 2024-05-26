from collections import defaultdict
import ipaddress
from pyshark.packet.packet import Packet
from reporter import Reporter
from attckes_templates.port_scan import PortScanDetector
from attckes_templates.ddos_attack import DDOSAttackDetector
from attckes_templates.sql_injection import SQLInjectionDetector
from attckes_templates.mac_flooding import MACFloodingDetector
from attckes_templates.arp_attack import ARPAttackDetector

class PacketFilter:
    def __init__(self, reporter: Reporter, config):
        self.reporter = reporter
        self.config = config
        self.detectors = [
            PortScanDetector(reporter, config),
            DDOSAttackDetector(reporter, config),
            SQLInjectionDetector(reporter, config),
            MACFloodingDetector(reporter, config),
            ARPAttackDetector(reporter, config)
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
            p = {
                'ipDst': packet.ip.dst,
                'ipSrc': packet.ip.src,
                'highest_layer': packet.highest_layer,
                'sniff_timestamp': packet.sniff_timestamp
            }
            self.reporter.report(p)
            return

        if packet.transport_layer in ['TCP', 'UDP']:
            if hasattr(packet, 'ip'):
                if self.is_private_ip(packet.ip.src) and self.is_private_ip(packet.ip.dst):
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

        for detector in self.detectors:
            detector.detect(packet)
