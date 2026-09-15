# frontend/pages/01_🔥_Upload_&_Analyze.py
import streamlit as st
import json
import requests

API_URL = "http://localhost:8000/analyze"

st.set_page_config(page_title="Upload & Analyze", page_icon="🔥", layout="wide")
st.title("🔥 Upload & Analyze")
st.markdown("Upload a SIEM alert JSON file or paste raw log text to run the full detection pipeline.")

tab1, tab2 = st.tabs(["📂 File Upload", "📋 Paste JSON"])

def run_analysis(payload: dict):
    with st.spinner("Running multi-agent analysis..."):
        try:
            resp = requests.post(API_URL, json={"event": payload}, timeout=60)
            if resp.status_code == 200:
                st.session_state["last_report"] = resp.json()
                st.success("✅ Analysis complete! View results in **Score Breakdown** or **Executive Report**.")
                st.json(resp.json())
            else:
                st.error(f"API Error {resp.status_code}: {resp.text}")
        except requests.exceptions.ConnectionError:
            st.error("❌ Cannot reach backend. Is `uvicorn backend.app:app` running on port 8000?")

# --- Tab 1: File Upload ---
with tab1:
    uploaded = st.file_uploader("Upload SIEM alert JSON", type=["json"])
    if uploaded:
        try:
            payload = json.load(uploaded)
            st.subheader("Parsed Event Preview")
            st.json(payload)
            if st.button("🚀 Analyze This Alert", key="file_btn"):
                run_analysis(payload)
        except json.JSONDecodeError:
            st.error("Invalid JSON file. Please upload a properly formatted alert.")

# --- Tab 2: Paste JSON ---
with tab2:
    sample = {
        "user_id": "EMP_042",
        "event_type": "usb_insert",
        "timestamp": "2024-06-14T23:45:00Z",
        "action": "USB device connected and files copied",
        "source_ip": "192.168.1.55",
        "bytes_transferred": 524288000,
        "after_hours": True,
        "device_id": "USB_8878",
    }
    raw_text = st.text_area(
        "Paste JSON log event:",
        value=json.dumps(sample, indent=2),
        height=280,
    )
    if st.button("🚀 Analyze Pasted Event", key="paste_btn"):
        try:
            payload = json.loads(raw_text)
            run_analysis(payload)
        except json.JSONDecodeError:
            st.error("Invalid JSON. Check your formatting.")