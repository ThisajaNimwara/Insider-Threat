# backend/agents/llm_agent_gemini.py
"""
Gemini LLM Agent — queries Google Gemini for global contextual audit.
Acts as a second-opinion auditor specifically tuned for false-positive reduction.
Receives the full enriched context plus prior agent scores before ruling.
"""

import os
import json
import re
import httpx
from typing import Optional

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = "gemini-1.5-flash"
GEMINI_API_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

PROMPT_PATH = os.path.join(
    os.path.dirname(__file__), "../prompts/gemini_second_opinion.txt"
)


class GeminiAgent:
    """
    Cross-examination auditor using Google Gemini.
    Receives full enriched context + prior agent scores, then delivers
    a calibrated score and explicit false-positive flag.
    """

    def __init__(self):
        self.api_key       = GEMINI_API_KEY
        self.system_prompt = self._load_prompt()
        self._has_key      = bool(self.api_key and self.api_key != "your_gemini_key_here")

    def _load_prompt(self) -> str:
        try:
            with open(PROMPT_PATH, "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return (
                "You are a cybersecurity auditor reviewing insider threat detection output. "
                "Return ONLY valid JSON with keys: threat_score (float 0-1), confidence (float 0-1), "
                "is_false_positive (bool), verdict (THREAT/BENIGN/INCONCLUSIVE), "
                "audit_notes (string), mitigating_factors (list), aggravating_factors (list)."
            )

    async def analyze(
        self,
        enriched_event: dict,
        prior_scores: Optional[dict] = None,
    ) -> dict:
        """
        Async — run Gemini audit on enriched event + prior agent context.

        Args:
            enriched_event : dict from enrichment.enrich_event()
            prior_scores   : optional {agent_name: score} from earlier agents

        Returns:
            dict with score, verdict, is_false_positive, audit_notes, factors
        """
        if not self._has_key:
            print("[GeminiAgent] No API key set — returning synthetic audit response.")
            return self._synthetic_response(enriched_event)

        full_prompt = (
            self.system_prompt
            + "\n\n"
            + self._build_user_message(enriched_event, prior_scores or {})
        )

        payload = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {
                "temperature":     0.05,
                "maxOutputTokens": 700,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{GEMINI_API_URL}?key={self.api_key}",
                    headers={"Content-Type": "application/json"},
                    json=payload,
                )
                resp.raise_for_status()
                raw_text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                return self._parse_response(raw_text)

        except httpx.HTTPStatusError as e:
            print(f"[GeminiAgent] HTTP {e.response.status_code}: {e.response.text}")
            return self._error_response(str(e))
        except (KeyError, IndexError) as e:
            print(f"[GeminiAgent] Unexpected response structure: {e}")
            return self._error_response(str(e))
        except Exception as e:
            print(f"[GeminiAgent] Unexpected error: {e}")
            return self._error_response(str(e))

    # ── Private helpers ────────────────────────────────────────────────────────

    def _build_user_message(self, enriched_event: dict, prior_scores: dict) -> str:
        prior_summary = (
            json.dumps(prior_scores, indent=2)
            if prior_scores
            else "No prior agent scores available."
        )
        return (
            "=== PRIOR AGENT SCORES ===\n"
            f"{prior_summary}\n\n"
            "=== ENRICHED EVENT DATA ===\n"
            f"{json.dumps(enriched_event, indent=2, default=str)}\n\n"
            "Audit the above and return ONLY valid JSON. "
            "Specifically consider whether a BENIGN explanation exists before confirming THREAT."
        )

    def _parse_response(self, raw_text: str) -> dict:
        cleaned = re.sub(r"```(?:json)?", "", raw_text).replace("```", "").strip()

        try:
            data = json.loads(cleaned)
            return {
                "agent":               "llm_gemini",
                "score":               self._safe_float(data.get("threat_score", 0.5)),
                "confidence":          self._safe_float(data.get("confidence", 0.60)),
                "is_false_positive":   bool(data.get("is_false_positive", False)),
                "verdict":             data.get("verdict", "INCONCLUSIVE"),
                "audit_notes":         data.get("audit_notes", ""),
                "mitigating_factors":  data.get("mitigating_factors", []),
                "aggravating_factors": data.get("aggravating_factors", []),
                "raw_output":          raw_text[:500],
            }
        except json.JSONDecodeError:
            score_match = re.search(r'"threat_score"\s*:\s*([\d.]+)', raw_text)
            fp_match    = re.search(r'"is_false_positive"\s*:\s*(true|false)', raw_text)
            return {
                "agent":               "llm_gemini",
                "score":               float(score_match.group(1)) if score_match else 0.50,
                "confidence":          0.35,
                "is_false_positive":   fp_match.group(1) == "true" if fp_match else False,
                "verdict":             "INCONCLUSIVE",
                "audit_notes":         raw_text[:300],
                "mitigating_factors":  [],
                "aggravating_factors": [],
                "parse_error":         True,
            }

    def _synthetic_response(self, enriched_event: dict) -> dict:
        """
        Rule-based fallback auditor when no Gemini key is configured.
        Explicitly looks for legitimate business-context explanations.
        """
        hr = enriched_event.get("hr_context", {})

        mitigating    = []
        aggravating   = []
        fp_likelihood = 0.0
        base_score    = 0.30

        role = hr.get("role", "").lower()
        dept = hr.get("department", "").lower()

        if any(r in role for r in ("admin", "it", "sysadmin", "devops")):
            mitigating.append("IT/Admin role may legitimately require after-hours access and USB usage.")
            fp_likelihood += 0.25
        if "backup" in dept or "ops" in dept:
            mitigating.append("Operations/Backup team routinely performs large scheduled transfers.")
            fp_likelihood += 0.20
        if not hr.get("resigned") and not hr.get("on_pip"):
            mitigating.append("No active HR risk flags (no PIP, no resignation) on record.")
            fp_likelihood += 0.15

        if hr.get("resigned"):
            aggravating.append("Active resignation dramatically increases data exfiltration motive.")
            base_score += 0.30
        if hr.get("on_pip"):
            aggravating.append("PIP status indicates strained employment relationship.")
            base_score += 0.20
        if enriched_event.get("after_hours"):
            aggravating.append("After-hours activity bypasses standard monitoring windows.")
            base_score += 0.10

        final_score = max(0.05, base_score - fp_likelihood * 0.40)
        is_fp       = fp_likelihood > 0.35 and final_score < 0.50
        verdict     = "BENIGN" if is_fp else ("THREAT" if final_score > 0.65 else "INCONCLUSIVE")

        return {
            "agent":               "llm_gemini",
            "score":               round(final_score, 4),
            "confidence":          0.60,
            "is_false_positive":   is_fp,
            "verdict":             verdict,
            "audit_notes": (
                f"Synthetic audit (no API key): {len(mitigating)} mitigating and "
                f"{len(aggravating)} aggravating factor(s) found. "
                f"FP probability: {fp_likelihood:.0%}. Verdict: {verdict}."
            ),
            "mitigating_factors":  mitigating,
            "aggravating_factors": aggravating,
            "synthetic":           True,
        }

    def _error_response(self, error_msg: str) -> dict:
        return {
            "agent":               "llm_gemini",
            "score":               0.50,
            "confidence":          0.25,
            "is_false_positive":   False,
            "verdict":             "INCONCLUSIVE",
            "audit_notes":         f"Audit unavailable due to API error: {error_msg[:200]}",
            "mitigating_factors":  [],
            "aggravating_factors": [],
            "error":               True,
        }

    @staticmethod
    def _safe_float(value) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.5