# backend/engine/scorer.py
"""
Computes ensemble weighted math to output a unified threat index (0.0 - 1.0).

Ensemble composition:
    Model 1  (catboost_insider_threat_model_v2)  — 20%  ML baseline (logistic ensemble)
    Model 2  (core + dfuse)                      — 30%  ML data fusion (split 16% / 14%)
    Model 3  (logon_pipeline_v2)                 — 20%  ML logon behaviour (GBM)
    Mistral  (LLM behavioural analyst)           — 15%  LLM first opinion
    Gemini   (LLM FP auditor)                   —  15%  LLM second opinion / calibration

Total: 100%
"""

from typing import Optional

# ── Weights — must sum to exactly 1.0 ─────────────────────────────────────────
WEIGHTS = {
    "ml_m1":       0.20,   # Model 1 : catboost_insider_threat_model_v2.pkl
    "ml_m2_core":  0.16,   # Model 2a: catboost core signal
    "ml_m2_dfuse": 0.14,   # Model 2b: catboost data fusion layer
    "ml_m3":       0.20,   # Model 3 : model3_logon_pipeline_v2 (bundled scaler + classifier)
    "llm_mistral": 0.15,   # LLM     : Mistral behavioural analyst
    "llm_gemini":  0.15,   # LLM     : Gemini FP auditor
}

# Convenience group totals (for display / validation)
WEIGHT_GROUPS = {
    "ml_model_1":  0.20,
    "ml_model_2":  0.30,   # core 0.16 + dfuse 0.14
    "ml_model_3":  0.20,
    "llm_total":   0.30,   # mistral 0.15 + gemini 0.15
}

RISK_THRESHOLDS = {
    "critical": 0.80,
    "high":     0.60,
    "medium":   0.40,
    "low":      0.00,
}


def compute_threat_index(
    ml_m1_score: float,
    ml_m2_core_score: float,
    ml_m2_dfuse_score: float,
    ml_m3_score: float,
    llm_mistral_score: float,
    llm_gemini_score: float,
) -> dict:
    """
    Compute the weighted ensemble threat index from all 5 model scores.

    Args:
        ml_m1_score       : float [0,1] — Model 1 (catboost_insider_threat_model_v2)
        ml_m2_core_score  : float [0,1] — Model 2 core signal (CatBoost)
        ml_m2_dfuse_score : float [0,1] — Model 2 data fusion layer (CatBoost)
        ml_m3_score       : float [0,1] — Model 3 (logon_pipeline_v2, bundled scaler + CatBoost)
        llm_mistral_score : float [0,1] — Mistral LLM analyst
        llm_gemini_score  : float [0,1] — Gemini LLM auditor

    Returns:
        dict with:
            unified_threat_index : float — final weighted score
            risk_level           : str   — low / medium / high / critical
            agent_scores         : dict  — clamped per-agent scores
            weights_applied      : dict  — weights used
            group_scores         : dict  — model-group subtotals
            weight_check         : float — sum of weights (should be 1.0)
    """
    scores = {
        "ml_m1":       _clamp(ml_m1_score),
        "ml_m2_core":  _clamp(ml_m2_core_score),
        "ml_m2_dfuse": _clamp(ml_m2_dfuse_score),
        "ml_m3":       _clamp(ml_m3_score),
        "llm_mistral": _clamp(llm_mistral_score),
        "llm_gemini":  _clamp(llm_gemini_score),
    }

    unified_score = sum(scores[k] * WEIGHTS[k] for k in scores)
    risk_level    = _classify_risk(unified_score)
    group_scores  = _compute_group_scores(scores)
    weight_check  = round(sum(WEIGHTS.values()), 10)

    return {
        "unified_threat_index": round(unified_score, 4),
        "risk_level":           risk_level,
        "agent_scores":         scores,
        "weights_applied":      WEIGHTS,
        "group_scores":         group_scores,
        "weight_check":         weight_check,
    }


def _compute_group_scores(scores: dict) -> dict:
    """
    Roll up individual agent scores into model-group subtotals.
    Useful for the dashboard breakdown — shows contribution per model group.

    Returns:
        dict of group_name → { weighted_contribution, raw_avg, weight }
    """
    groups = {
        "ml_model_1": {
            "keys":   ["ml_m1"],
            "weight": WEIGHT_GROUPS["ml_model_1"],
        },
        "ml_model_2": {
            "keys":   ["ml_m2_core", "ml_m2_dfuse"],
            "weight": WEIGHT_GROUPS["ml_model_2"],
        },
        "ml_model_3": {
            "keys":   ["ml_m3"],
            "weight": WEIGHT_GROUPS["ml_model_3"],
        },
        "llm_total": {
            "keys":   ["llm_mistral", "llm_gemini"],
            "weight": WEIGHT_GROUPS["llm_total"],
        },
    }

    result = {}
    for group_name, meta in groups.items():
        keys        = meta["keys"]
        raw_avg     = sum(scores[k] for k in keys) / len(keys)
        contribution = sum(scores[k] * WEIGHTS[k] for k in keys)
        result[group_name] = {
            "raw_avg":              round(raw_avg, 4),
            "weighted_contribution": round(contribution, 4),
            "group_weight":         meta["weight"],
        }

    return result


def validate_weights() -> bool:
    """
    Assert weights sum to 1.0.
    Call this at backend startup to catch any accidental drift.

    Returns:
        True if valid, raises ValueError if not.
    """
    total = round(sum(WEIGHTS.values()), 10)
    if total != 1.0:
        raise ValueError(
            f"[scorer] WEIGHTS do not sum to 1.0 — got {total}. "
            f"Individual weights: {WEIGHTS}"
        )
    return True


def _clamp(value: float) -> float:
    """Clamp a score to [0.0, 1.0], defaulting to 0.0 on bad input."""
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _classify_risk(score: float) -> str:
    """Map a unified score to a human-readable risk level."""
    for level, threshold in RISK_THRESHOLDS.items():
        if score >= threshold:
            return level
    return "low"