# backend/agents/ml_agent_m3.py
"""
ML Agent M3 - Gradient Boosting logon model (v2 pipeline).

v2 ships as a single bundled sklearn Pipeline (StandardScaler + CatBoost)
so there is no longer a separate scaler file to load.
"""

import joblib
import json
import numpy as np
import os

class MLAgentM3:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, "../../models/model 3/model3_logon_pipeline_v2.pkl")
        features_path = os.path.join(base_dir, "../../models/model 3/model3_feature_names.json")
        
        # v2 is a single Pipeline — scaler is baked in
        self.pipeline = joblib.load(model_path)
        with open(features_path) as f:
            data = json.load(f)
            # File contains {"feature_order": [...], ...} — extract the ordered list
            self.feature_names = data["feature_order"]
            
    def predict(self, features: np.ndarray, ev_dict: dict) -> dict:
        hour = features[0]
        day = features[1]
        after_hours = bool(features[2])
        is_weekend = bool(features[3])
        event_type = ev_dict.get("event_type", "")
        
        # Initialise all v2 features to 0.0 (safe defaults for single-event inference)
        feature_map = {name: 0.0 for name in self.feature_names}
            
        is_logon  = event_type == "logon"
        is_logoff = event_type == "logoff"
        
        # ── Core counts ────────────────────────────────────────────────────────
        feature_map["total_logons"]         = 1.0 if is_logon  else 0.0
        feature_map["total_logoffs"]        = 1.0 if is_logoff else 0.0
        feature_map["unique_pcs"]           = 1.0 if ev_dict.get("device_id") else 0.0
        feature_map["logons_afterhour"]     = 1.0 if is_logon  and after_hours else 0.0
        feature_map["weekend_logons"]       = 1.0 if is_logon  and is_weekend  else 0.0
        feature_map["afterhour_ratio"]      = 1.0 if after_hours else 0.0
        feature_map["unmatched_logons"]     = 0.0
        feature_map["avg_daily_logons"]     = 1.0
        feature_map["active_days"]          = 1.0
        # ── New v2 features ────────────────────────────────────────────────────
        feature_map["weekend_ratio"]        = 1.0 if is_weekend else 0.0
        feature_map["pcs_per_logon"]        = 1.0  # 1 unique PC / 1 logon this event
        feature_map["is_low_activity_window"] = 0.0  # unknown at single-event level
        
        X = np.array([[feature_map[f] for f in self.feature_names]])
        # Pipeline handles scaling internally — no manual scaler.transform needed
        prob = self.pipeline.predict_proba(X)[0][1]
        
        return {
            "score": round(float(prob), 4),
            "agent": "ml_m3"
        }