# backend/engine/enrichment.py
"""
Performs contextual lookups against local SQLite databases.
Enriches raw log events with HR status and incident history.
"""

from typing import Optional
from db.db_utils import get_employee, get_incident_summary


def enrich_event(user_id: str, event: dict) -> dict:
    """
    Enrich an incoming event with HR metadata and past incident flags.

    Args:
        user_id : employee identifier string
        event   : raw parsed log dict

    Returns:
        enriched dict with HR fields and incident history merged in
    """
    hr_context = get_employee(user_id)
    if hr_context is None:
        hr_context = {
            "employee_id": user_id,
            "on_pip": False,
            "resigned": False,
            "role": "unknown",
            "department": "unknown",
            "termination_date": None,
            "hire_date": None,
            "manager_id": None,
            "clearance_level": "standard",
            "remote_worker": 0,
        }

    incident_context = get_incident_summary(user_id)

    return {
        **event,
        "hr_context":       hr_context,
        "incident_context": incident_context,
    }