# backend/utils/parser.py
"""
Handles ingest validation for raw logs or SIEM JSON strings.
Normalises diverse input formats into a consistent internal schema.
"""

import json
from typing import Union
from pydantic import BaseModel, validator, Field
from datetime import datetime


REQUIRED_FIELDS = {"user_id", "event_type", "timestamp", "action"}

VALID_EVENT_TYPES = {
    "logon", "logoff", "file_access", "usb_insert",
    "usb_remove", "email_send", "web_browsing", "device_connect",
}


class LogEvent(BaseModel):
    user_id:     str
    event_type:  str
    timestamp:   str
    action:      str
    source_ip:   str  = Field(default="0.0.0.0")
    destination: str  = Field(default="")
    bytes_transferred: int = Field(default=0)
    after_hours: bool = Field(default=False)
    device_id:   str  = Field(default="")
    extra:       dict = Field(default_factory=dict)

    @validator("event_type")
    def validate_event_type(cls, v):
        if v not in VALID_EVENT_TYPES:
            raise ValueError(f"Unknown event_type '{v}'. Valid: {VALID_EVENT_TYPES}")
        return v

    @validator("timestamp")
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Invalid ISO 8601 timestamp: '{v}'")
        return v


def parse_event(raw_input: Union[str, dict]) -> LogEvent:
    """
    Parse and validate a raw log event from a string or dict.

    Args:
        raw_input: JSON string or already-parsed dict

    Returns:
        Validated LogEvent instance

    Raises:
        ValueError if input is malformed or missing required fields
    """
    if isinstance(raw_input, str):
        try:
            data = json.loads(raw_input)
        except json.JSONDecodeError as e:
            raise ValueError(f"[parser] Invalid JSON string: {e}")
    elif isinstance(raw_input, dict):
        data = raw_input
    else:
        raise TypeError(f"[parser] Expected str or dict, got {type(raw_input)}")

    missing = REQUIRED_FIELDS - set(data.keys())
    if missing:
        raise ValueError(f"[parser] Missing required fields: {missing}")

    return LogEvent(**data)