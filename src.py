from alert_system import alertSystem
from detection_system import detectionEngine
from capture_engine import packetCapture
from traffic_analysis import trafficAnalyzer
import argparse
import queue
import time
from scapy.all import IP, TCP, rdpcap

# LOF cannot fit on fewer samples than its n_neighbors setting.
MIN_BASELINE_SAMPLES = 20

class intrusionDetectionSystem:
    def __init__(self, interface="wlp1s0"):
        self.packet_capture = packetCapture()
        self.traffic_analyzer= trafficAnalyzer()
        self.detection_engine = detectionEngine()
        self.alert_system = alertSystem()

        self.interface = interface

    def load_baseline_from_pcap(self, path, benign_filter=None):
        packets = rdpcap(path)

        # A throwaway analyzer: reusing self.traffic_analyzer would leave the
        # pcap's flows in flow_stats and corrupt the rates of live traffic.
        analyzer = trafficAnalyzer()

        samples = []
        for packet in packets:
            if benign_filter and not benign_filter(packet):
                continue
            features = analyzer.analyze_packet(packet)
            if features:
                samples.append([
                    features['packet_size'],
                    features['packet_rate'],
                    features['byte_rate']
                ])
        return samples

    def train_from_pcap(self, path, benign_filter=None):
        print(f"Loading baseline from {path}...")
        samples = self.load_baseline_from_pcap(path, benign_filter)

        if len(samples) < MIN_BASELINE_SAMPLES:
            raise ValueError(
                f"Baseline has only {len(samples)} samples; LOF needs at least "
                f"{MIN_BASELINE_SAMPLES}. Capture a longer window."
            )

        print(f"Training model on {len(samples)} packets from pcap...")
        self.detection_engine.train_anomaly_detector(samples)
        print("Model trained.")

    def start(self, trained=False):
        print(f"Starting IDS on Interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        training_samples = []
        is_trained = trained
        start_time = time.time()

        if is_trained:
            print("IDS is ACTIVE (model pre-trained from pcap).")
        else:
            print("Phase 1: Collecting baseline traffic (5 seconds)...")

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    # Check if we are still in the training phase
                    if not is_trained:
                        training_samples.append([
                            features['packet_size'],
                            features['packet_rate'],
                            features['byte_rate']
                        ])

                        # Train once we have both enough time and enough samples
                        # for LOF to fit.
                        if (time.time() - start_time > 5
                                and len(training_samples) >= MIN_BASELINE_SAMPLES):
                            print(f"Training model on {len(training_samples)} packets...")
                            self.detection_engine.train_anomaly_detector(training_samples)
                            is_trained = True
                            print("Phase 2: IDS is now ACTIVE.")

                    # Only run detection if the model is ready
                    else:
                        threats = self.detection_engine.detect_threats(features)
                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport,
                                'destination_port': packet[TCP].dport
                            }
                            self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS.....")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network intrusion detection system")
    parser.add_argument("--interface", default="wlp1s0",
                        help="interface to sniff (default: wlp1s0)")
    parser.add_argument("--baseline-pcap",
                        help="train from this pcap instead of a live baseline window")
    args = parser.parse_args()

    ids = intrusionDetectionSystem(interface=args.interface)

    trained = False
    if args.baseline_pcap:
        ids.train_from_pcap(args.baseline_pcap)
        trained = True

    ids.start(trained=trained)
