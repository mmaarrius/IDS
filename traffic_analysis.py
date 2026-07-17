#TRAFFIC ANALYSIS MODULE  
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class trafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda:{
            'packet_count' : 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time  

            return self.extract_features(packet, stats)

    # A flow shorter than this has not run long enough for a rate over it to
    # mean anything; dividing by it manufactures huge spurious rates.
    MIN_RATE_DURATION = 0.01

    def extract_features(self, packet, stats):
        # packet.time is a Decimal; cast so downstream numpy gets plain floats.
        duration = float(stats['last_time'] - stats['start_time'])

        # Rates are only defined once a flow has real elapsed time. Reporting 0
        # rather than a rate divided by a fake floor keeps the invented ~10000
        # packets/s of a flow's first packet out of both training and detection.
        if duration < self.MIN_RATE_DURATION:
            packet_rate = 0.0
            byte_rate = 0.0
        else:
            packet_rate = stats['packet_count'] / duration
            byte_rate = stats['byte_count'] / duration

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window,
            'dest_port': packet[TCP].dport
        }