# backend/engine/report_builder.py
"""
Assembles agent decisions and enrichment data into a clean final JSON payload.
"""

from datetime import datetime, timezone
from typing import Optional


def build_report(
    event: dict,
    enriched_event: dict,
    scorer_result: dict,
    ml_m1_output: dict,
    ml_m2_core_output: dict,
    ml_m2_dfuse_output: dict,
    ml_m3_output: dict,
    mistral_output: dict,
    gemini_output: dict,
) -> dict:
    """
    Build the final structured JSON report for the API response.

    Returns:
        A fully assembled report dict ready for JSON serialisation.
    """
    return {
        "report_id":   _generate_report_id(event),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subject": {
            "user_id":     enriched_event.get("user_id", "unknown"),
            "hr_context":  enriched_event.get("hr_context", {}),
            "past_incidents": enriched_event.get("incident_context", {}),
        },
        "threat_assessment": {
            "unified_threat_index": scorer_result["unified_threat_index"],
            "risk_level":           scorer_result["risk_level"],
            "agent_scores":         scorer_result["agent_scores"],
            "weights_applied":      scorer_result["weights_applied"],
        },
        "agent_findings": {
            "ml_m1":       _safe_extract(ml_m1_output),
            "ml_m2_core":  _safe_extract(ml_m2_core_output),
            "ml_m2_dfuse": _safe_extract(ml_m2_dfuse_output),
            "ml_m3":       _safe_extract(ml_m3_output),
            "llm_mistral": _safe_extract(mistral_output),
            "llm_gemini":  _safe_extract(gemini_output),
        },
        "raw_event_summary": {
            "event_type": event.get("event_type"),
            "timestamp":  event.get("timestamp"),
            "source_ip":  event.get("source_ip"),
            "action":     event.get("action"),
        },
        "verdict": _compute_verdict(scorer_result["risk_level"]),
    }


def _generate_report_id(event: dict) -> str:
    ts  = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    uid = event.get("user_id", "anon")
    return f"RPT-{uid[:6].upper()}-{abs(hash(ts)) % 100000:05d}"


def _safe_extract(agent_output: dict) -> dict:
    """Return agent output safely, with a fallback."""
    if not isinstance(agent_output, dict):
        return {"error": "No output available", "score": 0.0}
    return agent_output


def _compute_verdict(risk_level: str) -> dict:
    verdicts = {
        "critical": {
            "action":      "ESCALATE IMMEDIATELY",
            "description": "High-confidence insider threat indicators detected. Recommend immediate account suspension and SOC review.",
            "color_code":  "#FF0000",
        },
        "high": {
            "action":      "INVESTIGATE",
            "description": "Multiple anomalous signals present. Flag for Tier-2 analyst review within 2 hours.",
            "color_code":  "#FF6600",
        },
        "medium": {
            "action":      "MONITOR",
            "description": "Mild deviations from baseline. Continue passive monitoring and correlate with additional signals.",
            "color_code":  "#FFCC00",
        },
        "low": {
            "action":      "NO ACTION",
            "description": "No significant threat signals detected. Event consistent with normal operational behaviour.",
            "color_code":  "#00CC44",
        },
    }
    return verdicts.get(risk_level, verdicts["low"])