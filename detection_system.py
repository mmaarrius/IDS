from sklearn.neighbors import LocalOutlierFactor
import numpy as np

class detectionEngine:
    
    def __init__(self):
        
        self.anomaly_detector = LocalOutlierFactor(n_neighbors=20, contamination=0.1, novelty=True)
        self.is_trained = False
        self.baseline_stats = {}
    
    def check_signature_rules(self, features):
        
        threats = []
        
        if features['tcp_flag'] == 2 and features['packet_rate'] > 100:
            threats.append({'type': 'signature', 'rule': 'syn_flood', 'confidence': '1.0'})
            
        if features['packet_size'] < 100 and features['packet_rate'] > 50:
            threats.append({'type': 'signature', 'rule': 'port_scan', 'confidence': '1.0'})
            
        if features.get('dest_port') in [21, 23]:
            threats.append({'type': 'signature', 'rule': 'dangerous_port', 'confidence': '1.0'})
            
        return threats
    
    def train_anomaly_detector(self, normal_traffic_data):
        
        data = np.array(normal_traffic_data)
        
        # we train the LOF on the normal data
        self.anomaly_detector.fit(data)
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
        ]])
 
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
 