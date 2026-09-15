# frontend/components/model_card.py
"""
Reusable model card component.
Displays training metadata, validation metrics, and feature importance
for each ML model used in the ensemble pipeline.
"""

import streamlit as st
import plotly.graph_objects as go
import json
import os
from typing import Optional


MODEL_METADATA_PATH = os.path.join(
    os.path.dirname(__file__), "../../models/model_metadata.json"
)

# Static fallback metadata if model_metadata.json is not yet generated
DEFAULT_METADATA = {
    "brian_insider_threat_model": {
        "display_name":     "ML Core — Logistic Ensemble (M1)",
        "model_type":       "Stacked Logistic Regression + Random Forest",
        "training_dataset": "CMU-CERT Insider Threat Dataset r4.2",
        "train_samples":    4520,
        "test_samples":     1130,
        "contamination_threshold": 0.08,
        "metrics": {
            "accuracy":  0.9310,
            "precision": 0.8874,
            "recall":    0.9122,
            "f1_score":  0.8996,
            "roc_auc":   0.9541,
        },
        "top_features": [
            {"feature": "resigned_flag",            "importance": 0.220},
            {"feature": "is_after_hours",           "importance": 0.195},
            {"feature": "has_usb_event",            "importance": 0.188},
            {"feature": "bytes_transferred_log",    "importance": 0.115},
            {"feature": "on_pip_flag",              "importance": 0.098},
            {"feature": "prior_incidents_count",    "importance": 0.082},
            {"feature": "known_baseline_deviation", "importance": 0.063},
            {"feature": "has_file_access",          "importance": 0.039},
        ],
        "weight_in_ensemble": 0.35,
    },
    "catboost_insider_threat_model": {
        "display_name":     "ML DFuse — CatBoost Data Fusion (M2)",
        "model_type":       "CatBoost Gradient Boosting with cross-signal fusion",
        "training_dataset": "CMU-CERT Insider Threat Dataset r4.2 + synthetic augmentation",
        "train_samples":    6840,
        "test_samples":     1710,
        "contamination_threshold": 0.08,
        "metrics": {
            "accuracy":  0.9478,
            "precision": 0.9231,
            "recall":    0.9087,
            "f1_score":  0.9158,
            "roc_auc":   0.9712,
        },
        "top_features": [
            {"feature": "resigned_flag × usb_event",         "importance": 0.310},
            {"feature": "is_after_hours × bytes_log",        "importance": 0.224},
            {"feature": "on_pip × file_access",              "importance": 0.163},
            {"feature": "prior_incidents × baseline_dev",    "importance": 0.121},
            {"feature": "weekend × usb_event",               "importance": 0.092},
            {"feature": "hour_of_day",                       "importance": 0.058},
            {"feature": "email_event × resigned",            "importance": 0.032},
        ],
        "weight_in_ensemble": 0.25,
    },
}


def load_model_metadata() -> dict:
    """Load model metadata from JSON or return defaults."""
    try:
        with open(MODEL_METADATA_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return DEFAULT_METADATA


def render_model_card(model_key: str, metadata: Optional[dict] = None) -> None:
    """
    Render a full model validation card for a given model key.

    Args:
        model_key : key in model_metadata.json (e.g. 'brian_insider_threat_model')
        metadata  : optional pre-loaded metadata dict
    """
    if metadata is None:
        metadata = load_model_metadata()

    info = metadata.get(model_key)
    if not info:
        st.warning(f"No metadata found for model key `{model_key}`")
        return

    metrics     = info.get("metrics", {})
    features    = info.get("top_features", [])
    model_name  = info.get("display_name", model_key)

    # Card header
    st.markdown(f"""
    <div style='
        border: 1px solid #333;
        border-radius: 8px;
        padding: 16px 20px 8px;
        margin-bottom: 16px;
        background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    '>
        <div style='font-size:11px; color:#58a6ff; letter-spacing:2px; text-transform:uppercase;'>
            MODEL CARD
        </div>
        <div style='font-size:20px; font-weight:700; margin: 4px 0 2px; color:#e6edf3;'>
            {model_name}
        </div>
        <div style='font-size:12px; color:#8b949e;'>
            {info.get('model_type', '')} &nbsp;·&nbsp;
            Ensemble weight: <b style='color:#58a6ff'>{info.get('weight_in_ensemble', 0):.0%}</b>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Training stats
    col1, col2, col3 = st.columns(3)
    col1.metric("Train Samples", f"{info.get('train_samples', 0):,}")
    col2.metric("Test Samples",  f"{info.get('test_samples', 0):,}")
    col3.metric("Contamination", f"{info.get('contamination_threshold', 0):.1%}")

    st.caption(f"📊 Dataset: {info.get('training_dataset', 'N/A')}")
    st.divider()

    # Metrics
    st.markdown("**Validation Metrics**")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Accuracy",  f"{metrics.get('accuracy',  0):.1%}")
    m2.metric("Precision", f"{metrics.get('precision', 0):.1%}")
    m3.metric("Recall",    f"{metrics.get('recall',    0):.1%}")
    m4.metric("F1 Score",  f"{metrics.get('f1_score',  0):.1%}")
    m5.metric("ROC-AUC",   f"{metrics.get('roc_auc',   0):.4f}")

    st.divider()

    # Feature importance bar chart
    if features:
        st.markdown("**Feature Importance**")
        feat_names   = [f["feature"]    for f in features]
        feat_imports = [f["importance"] for f in features]

        fig = go.Figure(go.Bar(
            x            = feat_imports,
            y            = feat_names,
            orientation  = "h",
            marker_color = [
                "#D32F2F" if v > 0.20 else
                "#E64A19" if v > 0.12 else
                "#F9A825" if v > 0.07 else
                "#2E7D32"
                for v in feat_imports
            ],
            text         = [f"{v:.1%}" for v in feat_imports],
            textposition = "outside",
        ))

        fig.update_layout(
            height      = max(180, len(features) * 34),
            margin      = dict(t=10, b=20, l=10, r=60),
            xaxis       = dict(range=[0, max(feat_imports) * 1.25],
                               showgrid=True, gridcolor="#222", tickformat=".0%"),
            yaxis       = dict(autorange="reversed", tickfont=dict(size=11)),
            paper_bgcolor = "rgba(0,0,0,0)",
            plot_bgcolor  = "rgba(0,0,0,0)",
            font_color    = "#CCCCCC",
            showlegend  = False,
        )

        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def render_all_model_cards() -> None:
    """Render cards for all models listed in metadata."""
    metadata = load_model_metadata()
    for model_key in metadata:
        render_model_card(model_key, metadata)
        st.markdown("---")


def render_ensemble_summary(metadata: Optional[dict] = None) -> None:
    """
    Render a compact summary comparing all models side-by-side.
    Intended for the Score Breakdown page header.
    """
    if metadata is None:
        metadata = load_model_metadata()

    st.markdown("#### Ensemble Model Summary")
    cols = st.columns(len(metadata))

    for col, (key, info) in zip(cols, metadata.items()):
        with col:
            metrics = info.get("metrics", {})
            st.markdown(
                f"""
                <div style='
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 12px;
                    text-align: center;
                    background: #0d1117;
                '>
                    <div style='font-size:10px; color:#58a6ff; letter-spacing:1px;'>
                        {info.get('weight_in_ensemble', 0):.0%} WEIGHT
                    </div>
                    <div style='font-size:13px; font-weight:600; margin: 6px 0 4px; color:#e6edf3;'>
                        {info.get('display_name', key)[:28]}
                    </div>
                    <div style='font-size:11px; color:#8b949e;'>
                        F1: <b style='color:#58a6ff'>{metrics.get('f1_score', 0):.1%}</b>
                        &nbsp;AUC: <b style='color:#58a6ff'>{metrics.get('roc_auc', 0):.3f}</b>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )