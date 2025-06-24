import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class ThreatDetectionEngine:
    def __init__(self):
        self.model = IsolationForest(contamination=0.15, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def prepare_features(self, df):
        """Extract simple features for ML"""
        features = df.copy()
        

        features['total_bytes'] = features['bytes_sent'] + features['bytes_received']
        features['total_packets'] = features['packets_sent'] + features['packets_received']
        features['bytes_per_packet'] = features['total_bytes'] / np.maximum(features['total_packets'], 1)
        features['is_high_port'] = (features['dest_port'] > 1024).astype(int)
        features['duration_log'] = np.log1p(features['duration'])
        

        feature_cols = ['total_bytes', 'total_packets', 'bytes_per_packet', 'is_high_port', 'duration_log']
        return features[feature_cols].fillna(0)
    
    def train(self, df):
        """Train the anomaly detection model"""
        X = self.prepare_features(df)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        return {"status": "trained", "samples": len(df)}
    
    def predict(self, df):
        """Predict anomalies in new data"""
        if not self.is_trained:
            return np.zeros(len(df))
        
        X = self.prepare_features(df)
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)
        
 
        anomalies = (predictions == -1).astype(int)
        
        return anomalies, scores
