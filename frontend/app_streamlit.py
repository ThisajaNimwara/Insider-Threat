# frontend/app_streamlit.py
"""Main Streamlit entrypoint. Run with: streamlit run frontend/app_streamlit.py"""

import streamlit as st

st.set_page_config(
    page_title="Insider Threat Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ Insider Threat Detection Platform")
st.markdown("""
Welcome to the **Insider Threat Detector** — a multi-agent AI pipeline combining:
- ☣ **ML Models** (CatBoost + Logistic Regression ensemble)
- ⚔ **LLM Agents** (Mistral for localized reasoning, Gemini for global audit)
- ⌨ **Contextual Enrichment** (HR status, incident history)

---

### 🚀 Getting Started
Use the sidebar to navigate between pipeline stages:

| Page | Purpose |
|------|---------|
| 🔥 Upload & Analyze | Submit a SIEM alert for full pipeline analysis |
| 📊 Score Breakdown | View per-agent telemetry, gauges, and confidence scores |
| 📝 Executive Report | Read and download the structured threat narrative |
""")

st.sidebar.success("Select a page above to begin.")

# Global session state initialization
if "last_report" not in st.session_state:
    st.session_state["last_report"] = None