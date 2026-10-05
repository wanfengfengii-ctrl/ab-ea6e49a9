"""Event payload validation and stable event digests."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from .signing import parse_timestamp


class EventValidationError(ValueError):
    """Payload is syntactically present but not a valid dose event."""


def canonical_digest(event: dict[str, Any]) -> str:
    """Stable SHA-256 hex digest of an event.

    Independent of key order, whitespace or gzip transport: canonical
    JSON with sorted keys, compact separators and UTF-8 code points.
    """
    blob = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def validate_event(data: Any, expected_station: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise EventValidationError("event payload must be a JSON object")

    event_id = data.get("event_id")
    if not isinstance(event_id, str) or not event_id.strip():
        raise EventValidationError("field 'event_id' must be a non-empty string")
    if len(event_id) > 200:
        raise EventValidationError("field 'event_id' is too long")

    measured_raw = data.get("measured_at")
    if not isinstance(measured_raw, str) or not measured_raw.strip():
        raise EventValidationError("field 'measured_at' must be an ISO-8601 timestamp string")
    try:
        measured_at = parse_timestamp(measured_raw)
    except (ValueError, OverflowError) as exc:
        raise EventValidationError(f"field 'measured_at' is invalid: {exc}") from exc
    if measured_at.year < 1990 or measured_at.year > 2100:
        raise EventValidationError("field 'measured_at' is out of plausible range")

    if "dose_uSv" not in data:
        raise EventValidationError("field 'dose_uSv' is required")
    dose = data["dose_uSv"]
    if isinstance(dose, bool) or not isinstance(dose, (int, float)):
        raise EventValidationError("field 'dose_uSv' must be a number")
    if not math.isfinite(dose) or dose < 0:
        raise EventValidationError("field 'dose_uSv' must be a finite, non-negative number")

    station_field = data.get("station")
    if station_field is not None and station_field != expected_station:
        raise EventValidationError("field 'station' does not match the authenticated station")

    return data
