# frontend/components/score_gauge.py
"""
Reusable Plotly gauge component for rendering threat risk scores.
Supports a compact mode (small inline) and a full-size hero mode.
"""

import plotly.graph_objects as go
import streamlit as st


RISK_PALETTE = {
    "critical": {"bar": "#D32F2F", "glow": "#FF5252", "label": "CRITICAL"},
    "high":     {"bar": "#E64A19", "glow": "#FF6E40", "label": "HIGH"},
    "medium":   {"bar": "#F9A825", "glow": "#FFD740", "label": "MEDIUM"},
    "low":      {"bar": "#2E7D32", "glow": "#69F0AE", "label": "LOW"},
}


def render_threat_gauge(
    score: float,
    risk_level: str,
    title: str = "Unified Threat Index",
    height: int = 320,
    show_delta: bool = False,
    prior_score: float | None = None,
) -> None:
    """
    Render a Plotly gauge showing the unified threat score.

    Args:
        score       : float 0.0–1.0
        risk_level  : 'critical' | 'high' | 'medium' | 'low'
        title       : chart title string
        height      : pixel height of the chart
        show_delta  : show delta annotation vs prior score
        prior_score : previous score for delta (optional)
    """
    palette  = RISK_PALETTE.get(risk_level, RISK_PALETTE["low"])
    pct      = round(score * 100, 1)
    delta_val = round((score - prior_score) * 100, 1) if (show_delta and prior_score is not None) else None

    fig = go.Figure(go.Indicator(
        mode  = "gauge+number" + ("+delta" if delta_val is not None else ""),
        value = pct,
        delta = {"reference": round(prior_score * 100, 1), "increasing": {"color": "#D32F2F"}} if delta_val else None,
        number = {
            "suffix":   "%",
            "font":     {"size": 42, "color": palette["bar"], "family": "Inter, sans-serif"},
        },
        title = {
            "text":     f"{title}<br><span style='font-size:14px;color:#888'>{palette['label']} RISK</span>",
            "font":     {"size": 16, "family": "Inter, sans-serif"},
        },
        gauge = {
            "axis": {
                "range":    [0, 100],
                "tickwidth": 1,
                "tickcolor": "#444",
                "tickfont":  {"size": 10},
            },
            "bar":   {"color": palette["bar"], "thickness": 0.28},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0,  40],  "color": "rgba(46,125,50,0.12)"},
                {"range": [40, 60],  "color": "rgba(249,168,37,0.12)"},
                {"range": [60, 80],  "color": "rgba(230,74,25,0.12)"},
                {"range": [80, 100], "color": "rgba(211,47,47,0.15)"},
            ],
            "threshold": {
                "line":  {"color": palette["glow"], "width": 3},
                "thickness": 0.85,
                "value": pct,
            },
        },
    ))

    fig.update_layout(
        height          = height,
        margin          = dict(t=60, b=20, l=30, r=30),
        paper_bgcolor   = "rgba(0,0,0,0)",
        plot_bgcolor    = "rgba(0,0,0,0)",
        font_color      = "#CCCCCC",
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def render_mini_gauge(
    score: float,
    risk_level: str,
    label: str,
    agent_name: str,
) -> None:
    """
    Compact inline gauge for per-agent score display.
    Intended to be placed inside st.columns().

    Args:
        score      : float 0.0–1.0
        risk_level : derived risk level for colour
        label      : display label (e.g. "ML Core")
        agent_name : short agent key for styling
    """
    palette = RISK_PALETTE.get(risk_level, RISK_PALETTE["low"])
    pct     = round(score * 100, 1)

    fig = go.Figure(go.Indicator(
        mode  = "gauge+number",
        value = pct,
        number = {"suffix": "%", "font": {"size": 24, "color": palette["bar"]}},
        title  = {"text": label, "font": {"size": 12}},
        gauge  = {
            "axis": {"range": [0, 100], "visible": False},
            "bar":  {"color": palette["bar"], "thickness": 0.30},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 100], "color": "rgba(255,255,255,0.05)"},
            ],
        },
    ))

    fig.update_layout(
        height        = 160,
        margin        = dict(t=40, b=10, l=10, r=10),
        paper_bgcolor = "rgba(0,0,0,0)",
        plot_bgcolor  = "rgba(0,0,0,0)",
        font_color    = "#CCCCCC",
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


def risk_level_from_score(score: float) -> str:
    """Convert a 0–1 float score into a risk level string."""
    if score >= 0.80:
        return "critical"
    elif score >= 0.60:
        return "high"
    elif score >= 0.40:
        return "medium"
    return "low"


def risk_badge(risk_level: str) -> str:
    """Return an HTML badge span for inline display in st.markdown()."""
    palette = RISK_PALETTE.get(risk_level, RISK_PALETTE["low"])
    return (
        f"<span style='background:{palette['bar']}22; color:{palette['bar']}; "
        f"border:1px solid {palette['bar']}55; padding:2px 10px; border-radius:4px; "
        f"font-weight:700; font-size:12px;'>{palette['label']}</span>"
    )