# backend/app.py
"""
FastAPI REST API entry point.
Endpoints: POST /analyze, GET /health
"""

import os
import sys
# Resolve python path to include backend directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Union
import traceback

from agents.ml_agent_m1 import MLAgentM1
from agents.ml_agent_core import MLAgentCore
from agents.ml_agent_dfuse import MLAgentDFuse
from agents.ml_agent_m3 import MLAgentM3
from agents.llm_agent_mistral import MistralAgent
from agents.llm_agent_gemini import GeminiAgent
from db.db_utils import log_analysis

from engine.scorer       import compute_threat_index
from engine.enrichment   import enrich_event
from engine.report_builder import build_report
from utils.parser         import parse_event
from utils.feature_extractor import extract_features

app = FastAPI(
    title="Insider Threat Detector API",
    description="Multi-agent ensemble threat detection pipeline",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialise agents once at startup
ml_m1       = MLAgentM1()
ml_m2_core  = MLAgentCore()
ml_m2_dfuse = MLAgentDFuse()
ml_m3       = MLAgentM3()
mistral     = MistralAgent()
gemini      = GeminiAgent()


class AnalyzeRequest(BaseModel):
    event: Union[dict, str]


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "insider-threat-detector"}


@app.post("/analyze")
async def analyze_event(request: AnalyzeRequest):
    """
    Full pipeline: parse → enrich → ML agents → LLM agents → score → report.
    """
    try:
        # 1. Parse & validate
        parsed  = parse_event(request.event)
        ev_dict = parsed.dict()

        # 2. Enrich with HR + incident context
        enriched = enrich_event(ev_dict["user_id"], ev_dict)

        # 3. Extract feature vector
        features = extract_features(ev_dict, enriched)

        # 4. ML agents
        m1_output    = ml_m1.predict(features, enriched)
        core_output  = ml_m2_core.predict(features, enriched)
        dfuse_output = ml_m2_dfuse.predict(features, enriched)
        m3_output    = ml_m3.predict(features, enriched)

        # 5. LLM agents
        mistral_output = await mistral.analyze(enriched)
        gemini_output  = await gemini.analyze(enriched)

        # 6. Score — 5-model weighted ensemble
        score_result = compute_threat_index(
            ml_m1_score       = m1_output["score"],
            ml_m2_core_score  = core_output["score"],
            ml_m2_dfuse_score = dfuse_output["score"],
            ml_m3_score       = m3_output["score"],
            llm_mistral_score = mistral_output["score"],
            llm_gemini_score  = gemini_output["score"],
        )

        # 7. Build report
        report = build_report(
            event              = ev_dict,
            enriched_event     = enriched,
            scorer_result      = score_result,
            ml_m1_output       = m1_output,
            ml_m2_core_output  = core_output,
            ml_m2_dfuse_output = dfuse_output,
            ml_m3_output       = m3_output,
            mistral_output     = mistral_output,
            gemini_output      = gemini_output,
        )

        # Log audit entry to database
        try:
            log_analysis(
                report_id         = report["report_id"],
                employee_id       = ev_dict["user_id"],
                event_type        = ev_dict["event_type"],
                scorer_result     = score_result,
                agent_scores      = score_result["agent_scores"],
                verdict           = score_result["risk_level"].upper(),
                is_false_positive = gemini_output.get("is_false_positive", False),
            )
        except Exception as db_err:
            print(f"[app] Failed to write analysis audit to database: {db_err}")

        return report

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail=traceback.format_exc())