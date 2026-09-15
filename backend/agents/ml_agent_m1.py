# backend/agents/ml_agent_m1.py
"""
ML Agent M1 - CatBoost Risk Profile Classifier (catboost_insider_threat_model_v2).

This model was trained on 35 risk-profile + physical-access features
(see models/model 1/model2_feature_names.json).  All 35 must be populated
from the enriched event dict; any that default to 0 / "unknown" will bias
the model toward a clean-baseline prediction and produce 0.0% risk scores.
"""

import joblib
import json
import math
import numpy as np
import os


class MLAgentM1:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path    = os.path.join(base_dir, "../../models/model 1/catboost_insider_threat_model_v2.pkl")
        features_path = os.path.join(base_dir, "../../models/model 1/model1_feature_names.json")
        metadata_path = os.path.join(base_dir, "../../models/model 1/model1_metadata.json")

        self.model = joblib.load(model_path)
        with open(features_path) as f:
            data = json.load(f)
            # File contains {"feature_order": [...], ...} — extract the ordered list
            self.feature_names = data["feature_order"]
        with open(metadata_path) as f:
            metadata = json.load(f)
            self.operating_threshold = float(metadata.get("operating_threshold", 0.35))

    # ──────────────────────────────────────────────────────────────────────────
    def predict(self, features: np.ndarray, ev_dict: dict) -> dict:
        import pandas as pd

        hr_ctx  = ev_dict.get("hr_context", {})
        inc_ctx = ev_dict.get("incident_context", {})
        event_type = ev_dict.get("event_type", "")

        # ── Seniority ──────────────────────────────────────────────────────────
        hire_date_str   = hr_ctx.get("hire_date")
        seniority_years = 3.0
        if hire_date_str:
            try:
                from datetime import datetime
                hire_date    = datetime.strptime(hire_date_str, "%Y-%m-%d")
                current_date = datetime(2026, 6, 21)
                seniority_years = max(0.0, (current_date - hire_date).days / 365.25)
            except Exception:
                pass

        if seniority_years < 1.0:
            seniority_bucket = "0-1"
        elif seniority_years < 3.0:
            seniority_bucket = "1-3"
        elif seniority_years < 5.0:
            seniority_bucket = "3-5"
        else:
            seniority_bucket = "5+"

        # ── Data-exfil / burn signals ──────────────────────────────────────────
        bytes_trans  = float(ev_dict.get("bytes_transferred", 0))
        is_usb_event = event_type in ("usb_insert", "usb_remove")
        extra        = ev_dict.get("extra", {})

        # total_files_burned = count of files actively copied / burned / exfiltrated.
        # NOTE: "files_accessed" (read-only) is intentionally excluded — it is a
        #       benign-read signal, not a copy/exfil signal.
        _explicit_copy_count  = extra.get("files_copied") or extra.get("files_exfiltrated")
        _repo_count           = extra.get("repos_cloned_count")  # git bulk-clone

        if _explicit_copy_count is not None:
            # Literal files-copied count — most accurate for USB exfil
            total_files_burned = float(_explicit_copy_count)

        elif _repo_count is not None:
            # Git clone: each "repo" contains many files.
            # Use max(reported repos, byte-based file estimate) so that a 3 GB
            # clone of 14 repos is scored on its actual data volume (~12 000 files),
            # not on the misleadingly small repo count.
            _byte_estimate     = float(max(1.0, bytes_trans / (256 * 1024)))
            total_files_burned = max(float(_repo_count), _byte_estimate)

        elif is_usb_event and bytes_trans > 0:
            # No literal count for USB — estimate from bytes (256 KB avg file size)
            total_files_burned = float(max(1.0, bytes_trans / (256 * 1024)))

        else:
            # logon, email, web, generic file_access without an exfil count → 0
            total_files_burned = 0.0

        burned_from_other = 0.0   # single-event inference: unknown source attribution

        # ── Print signals ──────────────────────────────────────────────────────
        # Prefer literal page count from event.extra; fall back to 4 KB/page estimate.
        is_print_event = event_type == "file_access" and ev_dict.get("action", "") == "print"
        pages_printed  = extra.get("pages_printed") or extra.get("printed_pages")
        if pages_printed is not None:
            total_printed_pages = float(pages_printed)
        elif is_print_event and bytes_trans > 0:
            total_printed_pages = float(max(1.0, bytes_trans // 4096))
        else:
            total_printed_pages = 0.0

        is_after_hours              = bool(ev_dict.get("after_hours", False))
        num_printed_pages_off_hours = total_printed_pages if is_after_hours else 0.0
        off_hours_print_ratio       = (num_printed_pages_off_hours / max(1.0, total_printed_pages))
        print_pages_log             = float(np.log1p(total_printed_pages))
        off_hours_pages_log         = float(np.log1p(num_printed_pages_off_hours))

        # ── Physical-access / travel signals ──────────────────────────────────
        # extra already extracted above
        is_abroad         = int(extra.get("is_abroad", 0))
        trip_day_number   = float(extra.get("trip_day_number", 0))
        # hostility_country_level: 0=none, 1=low, 2=medium, 3=high
        hostility_country_level = float(extra.get("hostility_country_level", 0))

        # Physical-access counts (single event = 1 entry)
        num_entries        = 1.0
        num_unique_campus  = 1.0
        # Use is_weekend from the base feature vector (index 3)
        entry_during_weekend = float(features[3])

        # ── Risk flags from HR / incident context ──────────────────────────────
        on_pip_flag    = float(features[9])
        resigned_flag  = float(features[10])
        # Some alert payloads embed an incident count directly in extra
        # (e.g. "previous_incidents": 2 in threat_002).  Take the higher of the
        # two so richer alert context is not silently discarded.
        _db_incidents    = float(inc_ctx.get("prior_incidents", 0))
        _extra_incidents = float(extra.get("previous_incidents", 0))
        prior_incidents  = max(_db_incidents, _extra_incidents)


        # Elevate hostility if user has resigned (potential disgruntled insider)
        if resigned_flag > 0 and hostility_country_level == 0:
            hostility_country_level = 1.0

        # HR risk profile flags
        is_contractor          = int(hr_ctx.get("is_contractor", 0))
        # employee_classification must be numeric — the model was trained on an ordinal encoding,
        # not as a CatBoost categorical column (it is absent from categorical_feature_indices).
        # Values observed in mock_hr.db: standard, elevated, admin
        _CLEARANCE_MAP = {
            "standard":     0,
            "elevated":     1,   # mid-level access (IT admins, HR coordinators, etc.)
            "admin":        2,   # administrative / system-level access
            "confidential": 1,
            "secret":       2,
            "top_secret":   3,
            "high":         3,   # treat "high" same as top_secret
        }
        _clearance_str     = str(hr_ctx.get("clearance_level", "standard")).lower()
        employee_classification_num = float(_CLEARANCE_MAP.get(_clearance_str, 0))
        employee_classification     = _clearance_str  # keep string only for high_risk_classification logic below
        has_foreign_citizenship = int(extra.get("has_foreign_citizenship", 0))
        has_criminal_record     = int(extra.get("has_criminal_record", 0))
        has_medical_history     = int(extra.get("has_medical_history", 0))

        # ── Engineered interaction / ratio features ────────────────────────────
        burn_from_other_ratio   = (burned_from_other / max(1.0, total_files_burned))
        files_burned_log        = float(np.log1p(total_files_burned))
        has_burned_files        = 1.0 if total_files_burned > 0 else 0.0
        has_burned_from_other   = 1.0 if burned_from_other  > 0 else 0.0
        hostility_x_abroad      = hostility_country_level * is_abroad
        hostility_x_foreign_citizen = hostility_country_level * has_foreign_citizenship
        trip_day_log            = float(np.log1p(trip_day_number))
        entries_x_weekend       = num_entries * entry_during_weekend
        multi_campus_flag       = 1.0 if num_unique_campus > 1 else 0.0

        # high_risk_classification: contract staff or high clearance (possible over-privilege)
        high_risk_classification = int(
            is_contractor == 1
            or employee_classification in ("top_secret", "secret", "admin", "high")
        )

        any_red_flag = 1.0 if (
            on_pip_flag > 0
            or resigned_flag > 0
            or prior_incidents > 0
            or has_criminal_record
            or total_files_burned > 0
            or hostility_x_abroad > 0
        ) else 0.0

        # ── Assemble feature map (must match model2_feature_names.json order) ──
        feature_map = {
            # Categorical
            "employee_department":         str(hr_ctx.get("department", "unknown")),
            "employee_campus":             str(extra.get("campus", "unknown")),
            "employee_position":           str(hr_ctx.get("role", "unknown")),
            # Numeric
            "employee_seniority_years":    float(seniority_years),
            "is_contractor":               float(is_contractor),
            "employee_classification":     employee_classification_num,   # numeric ordinal (0=standard … 3=top_secret)
            "has_foreign_citizenship":     float(has_foreign_citizenship),
            "has_criminal_record":         float(has_criminal_record),
            "has_medical_history":         float(has_medical_history),
            "employee_origin_country":     str(extra.get("origin_country", "US")),  # categorical
            # Print signals
            "total_printed_pages":         float(total_printed_pages),
            "num_printed_pages_off_hours": float(num_printed_pages_off_hours),
            # USB / burn signals
            "total_files_burned":          float(total_files_burned),
            "burned_from_other":           float(burned_from_other),
            # Travel
            "is_abroad":                   float(is_abroad),
            "trip_day_number":             float(trip_day_number),
            "hostility_country_level":     float(hostility_country_level),
            # Physical access
            "num_entries":                 float(num_entries),
            "num_unique_campus":           float(num_unique_campus),
            "entry_during_weekend":        float(entry_during_weekend),
            # Engineered ratio / log features
            "off_hours_print_ratio":       float(off_hours_print_ratio),
            "print_pages_log":             float(print_pages_log),
            "off_hours_pages_log":         float(off_hours_pages_log),
            "burn_from_other_ratio":       float(burn_from_other_ratio),
            "files_burned_log":            float(files_burned_log),
            "has_burned_files":            float(has_burned_files),
            "has_burned_from_other":       float(has_burned_from_other),
            # Interaction features
            "hostility_x_abroad":          float(hostility_x_abroad),
            "hostility_x_foreign_citizen": float(hostility_x_foreign_citizen),
            "trip_day_log":                float(trip_day_log),
            "entries_x_weekend":           float(entries_x_weekend),
            "multi_campus_flag":           float(multi_campus_flag),
            # Bucket / flag
            "seniority_bucket":            seniority_bucket,           # categorical
            "high_risk_classification":    float(high_risk_classification),
            "any_red_flag":                float(any_red_flag),
        }

        # Build DataFrame and enforce exact column order required by the model
        df = pd.DataFrame([feature_map])
        df = df[self.feature_names]

        # Predict probability of insider-threat class (class index 1). The saved
        # artifact is calibrated, so keep this raw value and derive a separate
        # alert score for the ensemble.
        prob = float(self.model.predict_proba(df)[0][1])
        score = self._calibrate_alert_score(
            raw_probability=prob,
            ev_dict=ev_dict,
            total_files_burned=total_files_burned,
            on_pip_flag=on_pip_flag,
            resigned_flag=resigned_flag,
            prior_incidents=prior_incidents,
        )

        return {
            "score":     round(float(score), 4),
            "raw_probability": round(float(prob), 4),
            "agent":     "ml_m1",
            "any_red_flag": bool(any_red_flag),
            "seniority_bucket": seniority_bucket,
        }

    def _calibrate_alert_score(
        self,
        raw_probability: float,
        ev_dict: dict,
        total_files_burned: float,
        on_pip_flag: float,
        resigned_flag: float,
        prior_incidents: float,
    ) -> float:
        """
        Convert M1's calibrated probability into an ensemble-facing alert score.

        M1 was trained on population-level profile data with a low positive
        class rate, so its probabilities are intentionally conservative. The
        ensemble needs a risk-intensity score for a single already-alerted event.
        """
        threshold = max(self.operating_threshold, 1e-6)
        model_score = math.sqrt(max(0.0, raw_probability) / threshold)
        model_score = float(np.clip(model_score, 0.0, 1.0))

        extra = ev_dict.get("extra", {}) or {}
        action = str(ev_dict.get("action", "")).lower()
        event_type = str(ev_dict.get("event_type", "")).lower()
        is_after_hours = bool(ev_dict.get("after_hours", False))

        evidence = 0.0
        if on_pip_flag > 0:
            evidence += 0.12
        if resigned_flag > 0 or extra.get("notice_period_active") or extra.get("resignation_date"):
            evidence += 0.12
        if prior_incidents > 0:
            evidence += min(0.14, 0.06 * prior_incidents)

        if total_files_burned > 0:
            evidence += 0.06
            if is_after_hours:
                evidence += 0.10
            if total_files_burned >= 1000:
                evidence += 0.04

        if extra.get("dlp_policy_triggered"):
            evidence += 0.10
        if extra.get("competitor_research_detected"):
            evidence += 0.07
        if extra.get("archive_created") or extra.get("repos_cloned_count"):
            evidence += 0.10
        if float(extra.get("anomaly_score_prior_week", 0) or 0) >= 0.5:
            evidence += 0.08

        if extra.get("credential_sharing_suspected"):
            evidence += 0.18
        impossible_minutes = extra.get("impossible_travel_minutes")
        if impossible_minutes is not None and float(impossible_minutes) <= 10:
            evidence += 0.16
        if float(extra.get("distance_km", 0) or 0) >= 1000:
            evidence += 0.06
        if len(extra.get("concurrent_sessions", []) or []) > 1:
            evidence += 0.07
        if extra.get("admin_portal_actions"):
            evidence += 0.10
        if extra.get("hr_investigation_open"):
            evidence += 0.08

        suspicious_terms = (
            "source code",
            "git",
            "repository",
            "archive",
            "removable",
            "usb",
            "credential",
            "impossible travel",
        )
        if any(term in action for term in suspicious_terms):
            evidence += 0.06
        if event_type in ("usb_insert", "usb_remove") and total_files_burned > 0:
            evidence += 0.08

        legitimate_context = 0.0
        if extra.get("manager_approved"):
            legitimate_context += 0.16
        if extra.get("on_call_schedule_confirmed"):
            legitimate_context += 0.18
        if extra.get("incident_ticket") or extra.get("pagerduty_alert_id"):
            legitimate_context += 0.12
        if extra.get("backup_policy_ref") or extra.get("verified_hash"):
            legitimate_context += 0.22
        if "backup" in action or str(extra.get("job_type", "")).startswith("scheduled_"):
            legitimate_context += 0.12

        contextual_score = float(np.clip(evidence - legitimate_context, 0.0, 0.85))
        return 1.0 - ((1.0 - model_score) * (1.0 - contextual_score))
