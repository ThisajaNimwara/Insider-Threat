# backend/utils/feature_extractor.py
"""
Transforms live log JSON events into feature vectors matching training data shape.
"""

from datetime import datetime
from typing import Any
import numpy as np


FEATURE_ORDER = [
    "hour_of_day",
    "day_of_week",
    "is_after_hours",
    "is_weekend",
    "bytes_transferred_log",
    "has_usb_event",
    "has_file_access",
    "has_email_event",
    "logon_count_proxy",
    "on_pip_flag",
    "resigned_flag",
    "prior_incidents_count",
    "known_baseline_deviation",
]


def extract_features(event: dict, enriched: dict) -> np.ndarray:
    """
    Convert a parsed + enriched event dict into a numeric feature vector.

    Args:
        event    : parsed LogEvent as dict
        enriched : enriched event dict (from enrichment.py)

    Returns:
        1D numpy array of shape (len(FEATURE_ORDER),)
    """
    ts = _parse_ts(event.get("timestamp", ""))
    hr_ctx  = enriched.get("hr_context", {})
    inc_ctx = enriched.get("incident_context", {})

    feature_map = {
        "hour_of_day":             ts.hour if ts else 12,
        "day_of_week":             ts.weekday() if ts else 0,
        "is_after_hours":          int(event.get("after_hours", False)),
        "is_weekend":              int(ts.weekday() >= 5) if ts else 0,
        "bytes_transferred_log":   _safe_log(event.get("bytes_transferred", 0)),
        "has_usb_event":           int(event.get("event_type") in ("usb_insert", "usb_remove")),
        "has_file_access":         int(event.get("event_type") == "file_access"),
        "has_email_event":         int(event.get("event_type") == "email_send"),
        "logon_count_proxy":       1,  # single event; historical roll-up handled by dfuse
        "on_pip_flag":             int(hr_ctx.get("on_pip", False)),
        "resigned_flag":           int(hr_ctx.get("resigned", False)),
        "prior_incidents_count":   min(inc_ctx.get("prior_incidents", 0), 10),  # cap at 10
        "known_baseline_deviation": int(inc_ctx.get("known_baseline_deviation", False)),
    }

    return np.array([feature_map[f] for f in FEATURE_ORDER], dtype=np.float32)


def get_feature_names() -> list[str]:
    """Return ordered list of feature names (matches training pipeline)."""
    return FEATURE_ORDER.copy()


def _parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _safe_log(value: Any) -> float:
    try:
        return float(np.log1p(max(0, int(value))))
    except (TypeError, ValueError):
        return 0.0