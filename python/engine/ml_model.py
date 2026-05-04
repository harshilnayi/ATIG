import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from typing import List, Dict, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'packet_size_mean', 'packet_size_std', 'packet_size_max',
            'flow_duration', 'packet_count', 'bytes_per_second',
            ' tcp_flag_count', 'dns_query_rate', 'connection_rate'
        ]

    def extract_features(self, packet_data: Dict) -> np.ndarray:
        features = []

        packet_sizes = packet_data.get('packet_sizes', [0])
        features.extend([
            np.mean(packet_sizes),
            np.std(packet_sizes) if len(packet_sizes) > 1 else 0,
            max(packet_sizes),
            packet_data.get('flow_duration', 0),
            packet_data.get('packet_count', 0),
            packet_data.get('bytes_per_second', 0),
            packet_data.get('tcp_flags', 0),
            packet_data.get('dns_queries', 0),
            packet_data.get('connections', 0)
        ])

        return np.array(features).reshape(1, -1)

    def train(self, features: np.ndarray):
        logger.info("training anomaly detection model...")
        self.scaler.fit(features)
        scaled_features = self.scaler.transform(features)
        self.model.fit(scaled_features)
        self.is_trained = True
        logger.info(f"model trained on {len(features)} samples")

    def predict(self, features: np.ndarray) -> Tuple[int, float]:
        if not self.is_trained:
            return 1, 0.5

        scaled = self.scaler.transform(features)
        prediction = self.model.predict(scaled)[0]
        score = self.model.score_samples(scaled)[0]

        normalized_score = (score + 1) / 2
        return prediction, normalized_score

    def is_anomaly(self, packet_data: Dict, threshold: float = 0.6) -> Tuple[bool, float]:
        features = self.extract_features(packet_data)
        prediction, score = self.predict(features)
        is_anomaly = prediction == -1 or score > threshold
        return is_anomaly, score

class BaselineLearner:
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.packet_sizes = []
        self.connection_rates = []
        self.dns_rates = []
        self.baseline = {}

    def add_sample(self, packet_data: Dict):
        self.packet_sizes.append(packet_data.get('packet_size', 0))
        self.connection_rates.append(packet_data.get('connections', 0))
        self.dns_rates.append(packet_data.get('dns_queries', 0))

        if len(self.packet_sizes) > self.window_size:
            self.packet_sizes = self.packet_sizes[-self.window_size:]
            self.connection_rates = self.connection_rates[-self.window_size:]
            self.dns_rates = self.dns_rates[-self.window_size:]

        self._update_baseline()

    def _update_baseline(self):
        self.baseline = {
            'packet_size_mean': np.mean(self.packet_sizes) if self.packet_sizes else 0,
            'packet_size_std': np.std(self.packet_sizes) if self.packet_sizes else 0,
            'connection_rate_mean': np.mean(self.connection_rates) if self.connection_rates else 0,
            'dns_rate_mean': np.mean(self.dns_rates) if self.dns_rates else 0,
        }

    def is_deviation(self, packet_data: Dict, std_threshold: float = 3.0) -> bool:
        if not self.baseline:
            return False

        packet_size = packet_data.get('packet_size', 0)
        mean = self.baseline.get('packet_size_mean', 0)
        std = self.baseline.get('packet_size_std', 0)

        if std == 0:
            return False

        z_score = abs(packet_size - mean) / std
        return z_score > std_threshold
