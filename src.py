from alert_system import alertSystem
from detection_system import detectionEngine
from capture_engine import packetCapture
from traffic_analysis import trafficAnalyzer
import argparse
import queue
import time
from scapy.all import IP, TCP, ARP, Ether, srp, rdpcap, conf


def resolve_mac(ip, iface, timeout=3):
    # Sends our own ARP request and waits for the real reply, out-of-band
    # from the sniffer. Used to seed a trusted mapping before capture
    # starts, so we don't have to rely on the target coincidentally
    # generating fresh legitimate ARP traffic (e.g. via a manual ping)
    # after an attack has already begun.
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=timeout, iface=iface, verbose=0)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

# LOF cannot fit on fewer samples than its n_neighbors setting.
MIN_BASELINE_SAMPLES = 20

# Seconds after the model goes active during which anomaly (not signature)
# alerts are suppressed, while fresh flows' rates settle down.
WARMUP_SECONDS = 5

# Only emit anomaly (zscore/lof) alerts at least this confident. Signatures are
# always 1.0, so this filters noise without touching real attack detections.
MIN_ANOMALY_CONFIDENCE = 0.9

# LOF/z-score run per packet, so one sustained anomalous flow floods hundreds of
# alerts. Emit at most one anomaly alert per source IP per this many seconds.
ANOMALY_COOLDOWN_SECONDS = 30

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

        # Seed the gateway's real MAC before sniffing starts. Without this,
        # check_arp_spoofing() would "learn" whichever MAC answers for the
        # gateway IP first as the trusted baseline -- if an attack is
        # already in progress (or starts before any other legitimate ARP
        # traffic occurs), that first reply could be the spoofed one, and
        # it would silently be accepted instead of flagged.
        _, _, gateway_ip = conf.route.route("0.0.0.0")
        gateway_mac = resolve_mac(gateway_ip, self.interface)
        if gateway_mac:
            self.detection_engine.seed_trusted_mapping(gateway_ip, gateway_mac)
            print(f"Seeded trusted mapping: {gateway_ip} -> {gateway_mac}")
        else:
            print(f"Warning: could not resolve gateway {gateway_ip} at startup; "
                  f"ARP-spoofing detection will trust whichever reply arrives first.")

        self.packet_capture.start_capture(self.interface)

        training_samples = []
        is_trained = trained
        start_time = time.time()

        # When the model goes active, live flows are all fresh and their rates
        # are volatile, producing a burst of anomaly false positives. Suppress
        # anomaly alerts (not signatures) for a short warm-up while flows settle.
        active_since = start_time if is_trained else None

        # source IP -> last time we emitted an anomaly alert for it (cooldown).
        anomaly_last_alert = {}

        if is_trained:
            print("IDS is ACTIVE (model pre-trained from pcap).")
        else:
            print("Phase 1: Collecting baseline traffic (5 seconds)...")

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)

                # ARP packets carry no IP/TCP layer, so they bypass the traffic
                # analyzer entirely and go straight to the ARP detector. This
                # runs regardless of the anomaly model's training state.
                if ARP in packet:
                    for threat in self.detection_engine.check_arp_spoofing(packet):
                        self.alert_system.generate_alert(threat, {
                            'source_ip': threat['ip'],
                            'destination_ip': None
                        })
                    continue

                # Port scan and SYN flood detection are stateful across packets
                # and do not depend on the anomaly model, so run them on every
                # TCP packet, including during the baseline phase.
                for threat in self.detection_engine.check_bruteforce(packet):
                    self.alert_system.generate_alert(threat, {
                        'source_ip': threat['source_ip'],
                        'destination_ip': threat['destination_ip']
                    })
                    
                for threat in self.detection_engine.check_port_scan(packet):
                    self.alert_system.generate_alert(threat, {
                        'source_ip': threat['ip'],
                        'destination_ip': packet[IP].dst
                    })

                for threat in self.detection_engine.check_syn_flood(packet):
                    self.alert_system.generate_alert(threat, {
                        'source_ip': threat['ip'],
                        'destination_ip': packet[IP].dst
                    })

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
                            active_since = time.time()
                            print("Phase 2: IDS is now ACTIVE.")

                    # Only run detection if the model is ready
                    else:
                        threats = self.detection_engine.detect_threats(features)

                        # Drop low-confidence anomaly alerts; signatures (1.0)
                        # always pass. Cuts most of the anomaly false-positive noise.
                        threats = [
                            t for t in threats
                            if t.get('type') != 'anomaly'
                            or t.get('confidence', 0) >= MIN_ANOMALY_CONFIDENCE
                        ]

                        # During warm-up, drop anomaly alerts (zscore/lof) while
                        # fresh flows settle; keep signature alerts (real attacks).
                        warming_up = time.time() - active_since < WARMUP_SECONDS
                        if warming_up:
                            threats = [t for t in threats if t.get('type') != 'anomaly']

                        # Cooldown: collapse a sustained anomalous flow's per-packet
                        # alerts into one per source IP per window. Signatures pass.
                        if any(t.get('type') == 'anomaly' for t in threats):
                            src = packet[IP].src
                            now = time.time()
                            if now - anomaly_last_alert.get(src, 0) < ANOMALY_COOLDOWN_SECONDS:
                                threats = [t for t in threats if t.get('type') != 'anomaly']
                            else:
                                anomaly_last_alert[src] = now

                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport,
                                'destination_port': packet[TCP].dport
                            }
                            self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                if self.packet_capture.capture_error:
                    print(f"Capture failed: {self.packet_capture.capture_error}")
                    if isinstance(self.packet_capture.capture_error, PermissionError):
                        print("Sniffing needs root. Try: sudo ./venv/bin/python src.py ...")
                    break
                continue
            except KeyboardInterrupt:
                print("Stopping IDS.....")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network intrusion detection system")
    parser.add_argument("--interface", default=None,
                        help="interface to sniff (default: system's default route)")
    parser.add_argument("--baseline-pcap",
                        help="train from this pcap instead of a live baseline window")
    args = parser.parse_args()

    # Fall back to the interface of the system's default route when unspecified.
    interface = args.interface or conf.route.route("0.0.0.0")[0]
    print(f"Using interface: {interface}")

    ids = intrusionDetectionSystem(interface=interface)

    trained = False
    if args.baseline_pcap:
        ids.train_from_pcap(args.baseline_pcap)
        trained = True

    ids.start(trained=trained)