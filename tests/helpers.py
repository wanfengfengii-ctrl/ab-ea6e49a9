"""Helpers for building authentically signed telemetry requests in tests."""

from __future__ import annotations

import base64
import gzip
import json
import time
from datetime import datetime, timezone

from app.signing import build_signing_text, compute_signature

EVENTS_PATH = "/api/telemetry/events"

KEYS = {
    ("ST01", "k1"): base64.b64decode("c3RhdGlvbi1zdC0xLXRlc3Qta2V5LXNlY3JldC0wMDAx"),
    ("ST02", "k1"): base64.b64decode("c3RhdGlvbi1zdC0yLXRlc3Qta2V5LXNlY3JldC0wMDAy"),
    ("ST03", "key-expired"): base64.b64decode("ZXhwaXJlZC1rZXktZm9yLXRlc3Rpbmctb25seQ=="),
}


def make_event(station: str = "ST01", **overrides) -> dict:
    event = {
        "event_id": "evt-0001",
        "station": station,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "dose_uSv": 0.37,
    }
    event.update(overrides)
    return event


def signed_headers(
    body: bytes,
    station: str = "ST01",
    key_id: str = "k1",
    secret: bytes | None = None,
    timestamp: str | None = None,
    nonce: str = "nonce-0001",
    method: str = "POST",
    path: str = EVENTS_PATH,
    gzipped: bool = False,
) -> dict[str, str]:
    if secret is None:
        secret = KEYS[(station, key_id)]
    if timestamp is None:
        timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-Station": station,
        "X-Key-Id": key_id,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
    }
    if gzipped:
        headers["Content-Encoding"] = "gzip"
    signing_text = build_signing_text(method, path, station, key_id, timestamp, nonce, body)
    headers["X-Signature"] = compute_signature(secret, signing_text)
    return headers


def encode_body(event: dict | list | str | bytes, gzipped: bool = False) -> bytes:
    if isinstance(event, bytes):
        raw = event
    elif isinstance(event, str):
        raw = event.encode("utf-8")
    else:
        raw = json.dumps(event).encode("utf-8")
    return gzip.compress(raw) if gzipped else raw
