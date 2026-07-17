from sklearn.neighbors import LocalOutlierFactor
import numpy as nm

class detectionEngine:
    
    def __init__(self):
        
        self.anomaly_detector = LocalOutlierFactor( n_neighbors=20, contamination=0.1, novelty=True)
        self.is_trained = False
        
        self.baseline_stats = {}
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
    