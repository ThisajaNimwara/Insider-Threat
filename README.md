```markdown
# 🛡️ Insider Threat Detection Tool

A multi-agent AI-powered insider threat detection platform designed to analyze SIEM (Security Information and Event Management) log events and identify potential security risks within an organization. The system combines machine learning anomaly detection with LLM-based reasoning in an ensemble pipeline to produce a unified threat score and executive-level reports.

---

## 🏗️ System Architecture

The pipeline processes input logs through enrichment, numerical feature extraction, ML/LLM scoring, and report generation:


```text
+-----------------------------------------------------------------------+
|                             SIEM Log Event                            |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                         Backend (FastAPI)                             |
|  1. Parse & Validate   -> Pydantic LogEvent                           |
|  2. HR Enrichment      -> SQLite (mock_hr.db, incident_history.db)     |
|  3. Feature Extractor  -> 13-Dimensional Feature Vector               |
+-----------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
         v                         v                         v
+-----------------+       +-----------------+       +-----------------+
|  ML Core Agent  |       | ML DFuse Agent  |       |   LLM Agents    |
| (GMM / IsoForest)       |(Data-Fusion GMM)  |       |(Mistral/Gemini) |
+-----------------+       +-----------------+       +-----------------+
         |                         |                         |
         +-------------------------+-------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                            Ensemble Scorer                            |
|          Weighted Score: Core (35%) + DFuse (25%) + LLMs (40%)        |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                         Frontend (Streamlit)                          |
|    Upload & Analyze  |  Score Breakdown  |  Executive Report          |
+-----------------------------------------------------------------------+

---

## 📂 Project Structure

```text
Insider Threat Detector/
├── backend/
│   ├── agents/
│   │   ├── ml_agent_core.py      # Core anomaly detection (GMM)
│   │   ├── ml_agent_dfuse.py     # Data-fusion anomaly detection
│   │   ├── ml_agent_m1.py        # CatBoost classifier (CERT dataset)
│   │   ├── ml_agent_m3.py        # Gradient Boosting logon model
│   │   ├── llm_agent_mistral.py  # Mistral threat analysis agent
│   │   └── llm_agent_gemini.py   # Gemini cross-examination agent
│   ├── db/
│   │   ├── db_utils.py           # Database query layer
│   │   ├── mock_hr.db            # Employee metadata (PIP, roles, clearance)
│   │   ├── incident_history.db   # Incident records and audit logs
│   │   └── seed_mock_data.py     # Database seeding script
│   ├── engine/
│   │   ├── scorer.py             # Weighted ensemble threat scoring
│   │   ├── enrichment.py         # Enriches events with HR & history context
│   │   └── report_builder.py     # Generates JSON executive reports
│   ├── prompts/
│   │   ├── prompt_loader.py      # Prompt template loader
│   │   ├── mistral_threat_analysis.txt
│   │   └── gemini_second_opinion.txt
│   ├── utils/
│   │   ├── parser.py             # SIEM log parsing via Pydantic
│   │   └── feature_extractor.py  # Feature extraction pipeline (13-dim)
│   └── app.py                    # FastAPI entrypoint (/analyze, /health)
├── frontend/
│   ├── app_streamlit.py          # Streamlit UI dashboard
│   ├── components/
│   │   ├── model_card.py         # Model metadata visualization widget
│   │   └── score_gauge.py        # Risk gauge Plotly component
│   └── pages/
│       ├── Upload_&_Analyze.py   # Log submission page
│       ├── Score_Breakdown.py    # Agent breakdown & visualization
│       └── Executive_Report.py   # Executive summary & report export
├── data/
│   └── mock_alerts/              # Sample benign and threat SIEM logs
└── models/                       # Trained ML model binaries (.pkl)

```

---

## ⚙️ 7-Stage Detection Pipeline

1. **Parse & Validate:** Input log JSON is validated against the `LogEvent` schema using Pydantic.
2. **Enrichment:** Queries SQLite to attach employee HR context (PIP status, resignation status) and incident history.
3. **Feature Extraction:** Transforms enriched logs into a 13-dimensional numerical vector.
4. **ML Analysis:** Runs anomaly scoring through ML Core and ML DFuse models.
5. **LLM Reasoning:** Evaluates behavioral context using Mistral (analysis) and Gemini (audit/cross-examination).
6. **Ensemble Scoring:** Computes a normalized risk score (0.0–1.0) using weighted contributions:
* **ML Core:** 35%
* **ML DFuse:** 25%
* **LLM Mistral:** 25%
* **LLM Gemini:** 15%


7. **Report Generation:** Produces a structured report containing threat level, component breakdowns, and actionable recommendations.

---

## 📊 Risk Scoring Matrix

| Score Range | Risk Level | Action Required |
| --- | --- | --- |
| **≥ 0.80** | 🔴 CRITICAL | Escalate Immediately |
| **≥ 0.60** | 🟠 HIGH | Investigate |
| **≥ 0.40** | 🟡 MEDIUM | Monitor |
| **< 0.40** | 🟢 LOW | No Action |

---

## 🚀 Getting Started

### Prerequisites

* Python 3.9+
* SQLite3

### 1. Environment Setup

Clone the repository and set up environment variables:

```bash
git clone [https://github.com/ThisajaNimwara/Insider-Threat.git](https://github.com/ThisajaNimwara/Insider-Threat.git)
cd Insider-Threat
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

```

Create a `.env` file in the root directory:

```env
MISTRAL_API_KEY=your_mistral_api_key
GEMINI_API_KEY=your_gemini_api_key

```

### 2. Database Initialization

Seed the SQLite databases:

```bash
python backend/db/seed_mock_data.py

```

### 3. Running the Application

**Start the FastAPI Backend:**

```bash
uvicorn backend.app:app --reload --port 8000

```

**Start the Streamlit Frontend:**

```bash
streamlit run frontend/app_streamlit.py

```

```

```
