# backend/agents/llm_agent_mistral.py
"""
Mistral LLM Agent — queries Mistral AI for localised behavioural reasoning.
Analyses enriched event context and produces a natural-language threat narrative
plus a numeric confidence score (0.0 – 1.0).
"""

import os
import json
import re
import httpx
from typing import Optional

MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "")
MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"
MISTRAL_MODEL   = "mistral-large-latest"

PROMPT_PATH = os.path.join(
    os.path.dirname(__file__), "../prompts/mistral_threat_analysis.txt"
)


class MistralAgent:
    """
    Sends enriched event context to Mistral and parses a structured threat verdict.
    Falls back to a rule-based synthetic response when no API key is configured.
    """

    def __init__(self):
        self.api_key       = MISTRAL_API_KEY
        self.system_prompt = self._load_prompt()
        self._has_key      = bool(self.api_key and self.api_key != "your_mistral_key_here")

    def _load_prompt(self) -> str:
        try:
            with open(PROMPT_PATH, "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return (
                "You are a senior SIEM analyst specialising in insider threat detection. "
                "Analyse the JSON event data provided and return ONLY valid JSON with keys: "
                "threat_score (float 0-1), confidence (float 0-1), verdict (THREAT/BENIGN/INCONCLUSIVE), "
                "reasoning (string, max 3 sentences), red_flags (list of strings)."
            )

    async def analyze(self, enriched_event: dict) -> dict:
        """
        Async — query Mistral with the enriched event context.

        Args:
            enriched_event: dict from enrichment.enrich_event()

        Returns:
            dict with score, verdict, reasoning, red_flags, confidence
        """
        if not self._has_key:
            print("[MistralAgent] No API key set — returning synthetic response.")
            return self._synthetic_response(enriched_event)

        payload = {
            "model":       MISTRAL_MODEL,
            "temperature": 0.1,
            "max_tokens":  600,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user",   "content": self._build_user_message(enriched_event)},
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    MISTRAL_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type":  "application/json",
                    },
                    json=payload,
                )
                resp.raise_for_status()
                raw_text = resp.json()["choices"][0]["message"]["content"]
                return self._parse_response(raw_text)

        except httpx.HTTPStatusError as e:
            print(f"[MistralAgent] HTTP {e.response.status_code}: {e.response.text}")
            return self._error_response(str(e))
        except Exception as e:
            print(f"[MistralAgent] Unexpected error: {e}")
            return self._error_response(str(e))

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_user_message(self, enriched_event: dict) -> str:
        return (
            "Analyse the following insider threat event and return a JSON verdict.\n\n"
            f"EVENT DATA:\n{json.dumps(enriched_event, indent=2, default=str)}\n\n"
            "Return ONLY valid JSON — no markdown, no preamble."
        )

    def _parse_response(self, raw_text: str) -> dict:
        """Extract and validate JSON from Mistral's response."""
        cleaned = re.sub(r"```(?:json)?", "", raw_text).replace("```", "").strip()

        try:
            data = json.loads(cleaned)
            return {
                "agent":      "llm_mistral",
                "score":      self._safe_float(data.get("threat_score", 0.5)),
                "confidence": self._safe_float(data.get("confidence", 0.65)),
                "verdict":    data.get("verdict", "INCONCLUSIVE"),
                "reasoning":  data.get("reasoning", "No reasoning provided."),
                "red_flags":  data.get("red_flags", []),
                "raw_output": raw_text[:500],
            }
        except json.JSONDecodeError:
            score_match = re.search(r'"threat_score"\s*:\s*([\d.]+)', raw_text)
            return {
                "agent":       "llm_mistral",
                "score":       float(score_match.group(1)) if score_match else 0.5,
                "confidence":  0.40,
                "verdict":     "INCONCLUSIVE",
                "reasoning":   raw_text[:300],
                "red_flags":   [],
                "parse_error": True,
            }

    def _synthetic_response(self, enriched_event: dict) -> dict:
        """
        Rule-based fallback when no Mistral key is configured.
        Keeps the pipeline functional during development.
        """
        hr  = enriched_event.get("hr_context", {})
        inc = enriched_event.get("incident_context", {})

        red_flags = []
        score     = 0.20

        if hr.get("resigned"):
            red_flags.append("Employee has active resignation")
            score += 0.30
        if hr.get("on_pip"):
            red_flags.append("Employee is on Performance Improvement Plan")
            score += 0.20
        if enriched_event.get("after_hours"):
            red_flags.append("Activity occurred outside business hours")
            score += 0.15
        if enriched_event.get("event_type") in ("usb_insert", "usb_remove"):
            red_flags.append("USB device activity detected")
            score += 0.20
        if inc.get("prior_incidents", 0) > 0:
            red_flags.append(f"{inc['prior_incidents']} prior incident(s) on record")
            score += 0.10

        score   = min(1.0, score)
        verdict = "THREAT" if score > 0.65 else ("INCONCLUSIVE" if score > 0.35 else "BENIGN")

        return {
            "agent":      "llm_mistral",
            "score":      round(score, 4),
            "confidence": 0.65,
            "verdict":    verdict,
            "reasoning": (
                f"Synthetic analysis (no API key): {len(red_flags)} risk indicator(s) identified. "
                f"Combined risk score is {score:.0%}. Verdict: {verdict}."
            ),
            "red_flags": red_flags,
            "synthetic": True,
        }

    def _error_response(self, error_msg: str) -> dict:
        return {
            "agent":      "llm_mistral",
            "score":      0.50,
            "confidence": 0.30,
            "verdict":    "INCONCLUSIVE",
            "reasoning":  f"Analysis unavailable due to API error: {error_msg[:200]}",
            "red_flags":  [],
            "error":      True,
        }

    @staticmethod
    def _safe_float(value) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.5