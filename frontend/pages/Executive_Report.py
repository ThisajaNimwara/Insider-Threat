# frontend/pages/03_📝_Executive_Report.py
import streamlit as st
import json
from datetime import datetime

st.set_page_config(page_title="Executive Report", page_icon="📝", layout="wide")
st.title("📝 Executive Threat Report")

report = st.session_state.get("last_report")

if not report:
    st.info("No analysis run yet. Go to **Upload & Analyze** first.")
    st.stop()

threat  = report["threat_assessment"]
verdict = report.get("verdict", {})
subject = report.get("subject", {})
hr      = subject.get("hr_context", {})
inc     = subject.get("past_incidents", {})
ev      = report.get("raw_event_summary", {})

RISK_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
emoji = RISK_EMOJI.get(threat["risk_level"], "⚪")

# --- Header ---
st.markdown(f"""
# {emoji} Threat Assessment — `{report.get('report_id', 'N/A')}`
**Generated:** {report.get('generated_at', 'N/A')}  
**Subject:** `{subject.get('user_id', 'Unknown')}`  
**Risk Level:** `{threat['risk_level'].upper()}`  
**Unified Threat Index:** `{threat['unified_threat_index']}`
""")

st.divider()

# --- Verdict ---
st.subheader("🔎 Verdict & Recommended Action")
action_color = verdict.get("color_code", "#888888")
st.markdown(
    f"""
    <div style='background:{action_color}22; border-left: 6px solid {action_color};
    padding: 12px 16px; border-radius: 6px;'>
    <h3 style='color:{action_color}; margin: 0'>{verdict.get('action', 'REVIEW')}</h3>
    <p style='margin: 4px 0 0'>{verdict.get('description', '')}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.divider()

# --- Event Summary ---
st.subheader("📌 Event Summary")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Event Type", ev.get("event_type", "—"))
col2.metric("Action",     ev.get("action", "—")[:30])
col3.metric("Source IP",  ev.get("source_ip", "—"))
col4.metric("Timestamp",  (ev.get("timestamp") or "—")[:16])

st.divider()

# --- HR & Incident Context ---
st.subheader("👤 Employee Context")
col_a, col_b = st.columns(2)
with col_a:
    st.markdown("**HR Status**")
    st.table({
        "Field": ["Role", "Department", "On PIP", "Resigned", "Termination Date"],
        "Value": [
            hr.get("role", "—"),
            hr.get("department", "—"),
            "⚠️ YES" if hr.get("on_pip") else "No",
            "⚠️ YES" if hr.get("resigned") else "No",
            hr.get("termination_date") or "—",
        ],
    })
with col_b:
    st.markdown("**Incident History**")
    st.table({
        "Field": ["Prior Incidents", "Last Incident", "Baseline Deviation"],
        "Value": [
            inc.get("prior_incidents", 0),
            inc.get("last_incident_ts") or "None",
            "⚠️ YES" if inc.get("known_baseline_deviation") else "No",
        ],
    })

st.divider()

# --- Agent Score Summary ---
st.subheader("🤖 Agent Score Summary")
scores  = threat["agent_scores"]
weights = threat["weights_applied"]
st.table({
    "Agent":          list(scores.keys()),
    "Score":          [f"{v:.4f}" for v in scores.values()],
    "Weight":         [weights[k] for k in scores],
    "Weighted Score": [f"{scores[k]*weights[k]:.4f}" for k in scores],
})

st.divider()

# --- Download ---
st.subheader("⬇️ Download Report")
report_json = json.dumps(report, indent=2)
st.download_button(
    label="📥 Download JSON Report",
    data=report_json,
    file_name=f"{report.get('report_id', 'threat_report')}.json",
    mime="application/json",
)

# PDF export hint
st.info("💡 To generate a PDF, install `reportlab` and call `report_builder.build_pdf(report)` — scaffold coming in the next phase.")