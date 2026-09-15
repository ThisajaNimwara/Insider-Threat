# backend/agents/ml_agent_dfuse.py
"""
ML DFuse Agent - data fusion anomaly detection with Isolation Forest.
"""

import joblib
import json
import numpy as np
import os

class MLAgentDFuse:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, "../../models/model 2/model2_dfuse_model.pkl")
        range_path = os.path.join(base_dir, "../../models/model 2/dfuse_score_range.json")
        
        self.model = joblib.load(model_path)
        with open(range_path) as f:
            self.range = json.load(f)
            
    def predict(self, features: np.ndarray, ev_dict: dict) -> dict:
        X = features.reshape(1, -1)
        raw_score = -self.model.score_samples(X)[0]
        norm = (raw_score - self.range['min']) / (self.range['max'] - self.range['min'])
        score = float(np.clip(norm, 0.0, 1.0))
        return {
            "score": round(score, 4),
            "raw_score": round(raw_score, 4),
            "agent": "ml_m2_dfuse"
        }