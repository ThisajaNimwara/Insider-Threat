# backend/prompts/prompt_loader.py
"""
Centralised prompt loader for all LLM agents.

Responsibilities:
  - Load prompt templates from .txt files with caching
  - Inject runtime variables into prompt templates via {placeholder} syntax
  - Validate that required variables are present before injection
  - Provide a registry of all available prompts with metadata

Usage:
    from backend.prompts.prompt_loader import load_prompt, render_prompt

    # Load raw template
    template = load_prompt("mistral_threat_analysis")

    # Load and inject variables
    filled = render_prompt(
        "gemini_second_opinion",
        variables={"event_json": json.dumps(event), "prior_scores": "..."}
    )
"""

import os
import re
from functools import lru_cache
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────────
_PROMPTS_DIR = os.path.dirname(__file__)

# ── Prompt registry ────────────────────────────────────────────────────────────
# Maps a stable key → filename (without .txt) + metadata
PROMPT_REGISTRY: dict[str, dict] = {
    "mistral_threat_analysis": {
        "file":        "mistral_threat_analysis.txt",
        "agent":       "llm_mistral",
        "description": "Primary behavioural anomaly classification prompt for Mistral.",
        "required_vars": [],   # no inline {vars} — context injected as user message
        "version":     "1.0",
    },
    "gemini_second_opinion": {
        "file":        "gemini_second_opinion.txt",
        "agent":       "llm_gemini",
        "description": "Cross-examination / false-positive audit prompt for Gemini.",
        "required_vars": [],   # no inline {vars} — context injected as user message
        "version":     "1.0",
    },
}


# ── Core loader ────────────────────────────────────────────────────────────────

@lru_cache(maxsize=16)
def load_prompt(prompt_key: str) -> str:
    """
    Load and cache a prompt template by its registry key.

    Args:
        prompt_key : key from PROMPT_REGISTRY (e.g. 'mistral_threat_analysis')

    Returns:
        Raw prompt string.

    Raises:
        KeyError     if prompt_key is not in the registry.
        FileNotFoundError if the .txt file is missing from disk.
    """
    if prompt_key not in PROMPT_REGISTRY:
        raise KeyError(
            f"Unknown prompt key '{prompt_key}'. "
            f"Available: {list(PROMPT_REGISTRY.keys())}"
        )

    filename  = PROMPT_REGISTRY[prompt_key]["file"]
    file_path = os.path.join(_PROMPTS_DIR, filename)

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"Prompt file not found: {file_path}. "
            f"Ensure '{filename}' exists in backend/prompts/."
        )

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        raise ValueError(f"Prompt file '{filename}' is empty.")

    return content


def render_prompt(
    prompt_key: str,
    variables: Optional[dict[str, str]] = None,
) -> str:
    """
    Load a prompt template and inject runtime variables.

    Placeholders in the template use Python's {variable_name} syntax.
    Only placeholders explicitly provided in `variables` are replaced —
    unknown placeholders are left as-is (safe for partial injection).

    Args:
        prompt_key : registry key for the prompt
        variables  : dict of {placeholder: value} pairs to inject

    Returns:
        The prompt string with variables injected.

    Raises:
        ValueError if a required variable from the registry is missing.
    """
    template = load_prompt(prompt_key)

    if not variables:
        return template

    # Validate required variables are present
    required = PROMPT_REGISTRY[prompt_key].get("required_vars", [])
    missing  = [v for v in required if v not in variables]
    if missing:
        raise ValueError(
            f"Prompt '{prompt_key}' requires variables not provided: {missing}"
        )

    # Safe substitution — only replace provided keys, leave others intact
    result = template
    for key, value in variables.items():
        result = result.replace("{" + key + "}", str(value))

    return result


def reload_prompt(prompt_key: str) -> str:
    """
    Force-reload a prompt from disk, bypassing the LRU cache.
    Useful during development when editing prompt files live.

    Args:
        prompt_key : registry key for the prompt

    Returns:
        Freshly loaded prompt string.
    """
    load_prompt.cache_clear()
    return load_prompt(prompt_key)


# ── Introspection helpers ──────────────────────────────────────────────────────

def list_prompts() -> list[dict]:
    """
    Return metadata for all registered prompts.
    Used by GET /health and the docs page.
    """
    prompts = []
    for key, meta in PROMPT_REGISTRY.items():
        file_path = os.path.join(_PROMPTS_DIR, meta["file"])
        exists    = os.path.exists(file_path)
        size_bytes = os.path.getsize(file_path) if exists else 0

        prompts.append({
            "key":           key,
            "file":          meta["file"],
            "agent":         meta["agent"],
            "description":   meta["description"],
            "version":       meta["version"],
            "required_vars": meta["required_vars"],
            "file_exists":   exists,
            "size_bytes":    size_bytes,
        })

    return prompts


def get_prompt_placeholders(prompt_key: str) -> list[str]:
    """
    Parse and return all {placeholder} names found in a prompt template.
    Useful for tooling / prompt testing.
    """
    template     = load_prompt(prompt_key)
    placeholders = re.findall(r"\{(\w+)\}", template)
    return list(dict.fromkeys(placeholders))   # deduplicated, order preserved


def health_check_prompts() -> dict:
    """
    Verify all registered prompt files are present and non-empty.
    Called by GET /health in app.py.
    """
    results = {}
    for key, meta in PROMPT_REGISTRY.items():
        file_path = os.path.join(_PROMPTS_DIR, meta["file"])
        try:
            content  = load_prompt(key)
            results[key] = {
                "status":      "ok",
                "size_bytes":  len(content.encode("utf-8")),
                "version":     meta["version"],
            }
        except (FileNotFoundError, ValueError) as e:
            results[key] = {"status": "error", "error": str(e)}

    return results