# backend/prompts/__init__.py
"""
Prompts module public API.
All agents load prompts through here — never open .txt files directly.
"""

from .prompt_loader import (
    load_prompt,
    render_prompt,
    reload_prompt,
    list_prompts,
    get_prompt_placeholders,
    health_check_prompts,
    PROMPT_REGISTRY,
)

__all__ = [
    "load_prompt",
    "render_prompt",
    "reload_prompt",
    "list_prompts",
    "get_prompt_placeholders",
    "health_check_prompts",
    "PROMPT_REGISTRY",
]