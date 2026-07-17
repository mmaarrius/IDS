from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from scapy.all import ARP, IP, TCP
from collections import defaultdict
import time
import numpy as np

class detectionEngine:

    def __init__(self):

        # contamination is the share of traffic LOF is told to call anomalous.
        # At 0.1 it flagged ~10% of a baseline we believe is clean; 0.01 asks it
        # to reserve the label for genuine outliers.
        self.anomaly_detector = LocalOutlierFactor(n_neighbors=20, contamination=0.01, novelty=True)
        # LOF is distance-based and byte_rate is orders of magnitude larger than
        # packet_size, so without scaling it would dominate the metric entirely.
        self.scaler = StandardScaler()
        self.is_trained = False
        self.baseline_stats = {}

        # Maps each IP to the MAC address we first saw it use. An IP suddenly
        # answering from a different MAC is the classic ARP spoofing signature.
        self.ip_mac_table = {}

        # Per-source-IP record of (destination_port -> last time seen), for port
        # scan detection. A real scan is one source touching many distinct ports
        # in a short window; a normal download touches one. Old entries are aged
        # out so this cannot grow without bound.
        self.port_access = defaultdict(dict)
        self.PORT_SCAN_WINDOW = 5.0     # seconds a port access stays "recent"
        self.PORT_SCAN_THRESHOLD = 15   # distinct ports in the window -> scan
        # Fire at most once per source per window, so one scan is one alert, not
        # one per packet.
        self.last_scan_alert = {}

    def check_port_scan(self, packet, now=None):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return []

        now = time.time() if now is None else now
        src = packet[IP].src
        dport = packet[TCP].dport

        ports = self.port_access[src]
        ports[dport] = now

        # Age out ports last seen longer ago than the window.
        cutoff = now - self.PORT_SCAN_WINDOW
        for p in [p for p, t in ports.items() if t < cutoff]:
            del ports[p]

        if len(ports) < self.PORT_SCAN_THRESHOLD:
            return []

        # Don't re-alert for the same ongoing scan within one window.
        last = self.last_scan_alert.get(src, 0)
        if now - last < self.PORT_SCAN_WINDOW:
            return []
        self.last_scan_alert[src] = now

        return [{
            'type': 'signature',
            'rule': 'port_scan',
            'ip': src,
            'distinct_ports': len(ports),
            'confidence': 1.0
        }]

    def check_arp_spoofing(self, packet):
        # Only ARP replies (op == 2) assert "this IP is at this MAC"; requests
        # (op == 1) are just questions and carry no binding to trust.
        if not packet.haslayer(ARP) or packet[ARP].op != 2:
            return []

        claimed_ip = packet[ARP].psrc
        claimed_mac = packet[ARP].hwsrc

        known_mac = self.ip_mac_table.get(claimed_ip)
        if known_mac is None:
            # First time we see this IP; learn it, nothing to flag yet.
            self.ip_mac_table[claimed_ip] = claimed_mac
            return []

        if known_mac != claimed_mac:
            # Same IP now answering from a different MAC -> likely spoofing.
            return [{
                'type': 'signature',
                'rule': 'arp_spoofing',
                'ip': claimed_ip,
                'original_mac': known_mac,
                'new_mac': claimed_mac,
                'confidence': 1.0
            }]
        return []

    def check_signature_rules(self, features):
        
        threats = []
        
        if features['tcp_flags'] == 2 and features['packet_rate'] > 100:
            threats.append({'type': 'signature', 'rule': 'syn_flood', 'confidence': 1.0})

        if features.get('dest_port') in [21, 23]:
            threats.append({'type': 'signature', 'rule': 'dangerous_port', 'confidence': 1.0})
            
        return threats
    
    def train_anomaly_detector(self, normal_traffic_data):
        
        data = np.array(normal_traffic_data, dtype=float)

        # we train the LOF on the scaled normal data
        self.anomaly_detector.fit(self.scaler.fit_transform(data))
        self.is_trained = True
        
        # we calculate the mean and the standard deviation on each collumn for the Z-score
        self.baseline_stats = {
            'packet_size': {'mean': data[:, 0].mean(), 'std': data[:, 0].std()},
            'packet_rate': {'mean': data[:, 1].mean(), 'std': data[:, 1].std()},
            'byte_rate':   {'mean': data[:, 2].mean(), 'std': data[:, 2].std()},
        }
 
    def check_zscore(self, features, threshold=3.0):
        
        anomalies = []
        
        for feature_name in ['packet_size', 'packet_rate', 'byte_rate']:
            stats = self.baseline_stats.get(feature_name)
            
            # we avoid division by 0
            if not stats or stats['std'] == 0:
                continue
 
            z = (features[feature_name] - stats['mean']) / stats['std']
            
            if abs(z) > threshold:
                anomalies.append({
                    'type': 'anomaly',          
                    'method': 'zscore',         
                    'feature': feature_name,
                    'z_score': round(float(z), 2),
                    'confidence': min(1.0, abs(z) / (threshold * 2))
                })
        return anomalies
 
    
    def check_lof(self, features):
        if not self.is_trained:
            return []
 
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]], dtype=float)

        # must reuse the scaler fitted on the baseline, not refit it here
        feature_vector = self.scaler.transform(feature_vector)

        # we'll predict 1 to be normal and -1 an anomaly
        prediction = self.anomaly_detector.predict(feature_vector)[0]

        if prediction == -1:
            score = self.anomaly_detector.decision_function(feature_vector)[0]
            return [{
                'type': 'anomaly',
                'method': 'lof',
                'score': round(float(score), 3),
                'confidence': min(1.0, abs(score))
            }]
        return []
 
   
    def detect_threats(self, features):
       
        # we always detect the signature based anomalies even if the model is not trained
        threats = self.check_signature_rules(features)

        # we extend the list with the Zscore anomalies
        threats.extend(self.check_zscore(features))
 
        # we make sure the model is trained before adding the outliers
        try:
            threats.extend(self.check_lof(features))
        except Exception:
            pass
        
        return threats
 