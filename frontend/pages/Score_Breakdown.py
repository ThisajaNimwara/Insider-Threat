# frontend/pages/02_📊_Score_Breakdown.py
import streamlit as st
import plotly.graph_objects as go

st.set_page_config(page_title="Score Breakdown", page_icon="📊", layout="wide")
st.title("📊 Multi-Agent Score Breakdown")

report = st.session_state.get("last_report")

if not report:
    st.info("No analysis run yet. Go to **Upload & Analyze** first.")
    st.stop()

threat = report["threat_assessment"]
scores = threat["agent_scores"]
weights = threat["weights_applied"]
unified = threat["unified_threat_index"]
risk    = threat["risk_level"]

RISK_COLORS = {
    "critical": "#FF0000",
    "high":     "#FF6600",
    "medium":   "#FFCC00",
    "low":      "#00CC44",
}
color = RISK_COLORS.get(risk, "#888888")

# --- Unified Gauge ---
st.subheader("Unified Threat Index")
fig_gauge = go.Figure(go.Indicator(
    mode="gauge+number+delta",
    value=round(unified * 100, 1),
    domain={"x": [0, 1], "y": [0, 1]},
    title={"text": f"Risk Level: <b>{risk.upper()}</b>", "font": {"size": 20}},
    gauge={
        "axis": {"range": [0, 100], "tickwidth": 1},
        "bar":  {"color": color},
        "steps": [
            {"range": [0, 40],  "color": "#e8f5e9"},
            {"range": [40, 60], "color": "#fff9c4"},
            {"range": [60, 80], "color": "#ffe0b2"},
            {"range": [80, 100],"color": "#ffcdd2"},
        ],
        "threshold": {"line": {"color": "black", "width": 4}, "value": unified * 100},
    },
))
st.plotly_chart(fig_gauge, use_container_width=True)

# --- Agent Score Bars ---
st.subheader("Per-Agent Scores")
cols = st.columns(len(scores))
agent_labels = {
    "ml_core":     "🤖 ML Core",
    "ml_dfuse":    "🔀 ML DFuse",
    "llm_mistral": "💬 Mistral",
    "llm_gemini":  "🌐 Gemini",
}
for col, (agent_key, score) in zip(cols, scores.items()):
    with col:
        pct = round(score * 100, 1)
        st.metric(
            label=agent_labels.get(agent_key, agent_key),
            value=f"{pct}%",
            delta=f"weight: {weights[agent_key]}",
        )
        st.progress(score)

# --- Agent Findings ---
st.subheader("Agent Reasoning")
findings = report.get("agent_findings", {})
for agent, data in findings.items():
    with st.expander(f"📋 {agent_labels.get(agent, agent)} findings"):
        st.json(data)

# --- Subject Context ---
st.subheader("Subject Context")
subject = report.get("subject", {})
c1, c2 = st.columns(2)
with c1:
    st.json(subject.get("hr_context", {}))
with c2:
    st.json(subject.get("past_incidents", {}))