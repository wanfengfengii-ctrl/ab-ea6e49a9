"""Request signing and signature verification.

The signed payload is the following fields joined by ``"\\n"``::

    METHOD
    /api/telemetry/events
    <X-Station>
    <X-Key-Id>
    <X-Timestamp>
    <X-Nonce>
    <sha256 hex of the raw transmitted request body bytes>

HMAC-SHA256 is computed with the station key's shared secret and the
result is carried (standard Base64) in ``X-Signature``. When the body is
gzip-compressed the hash covers the *compressed* bytes actually put on the
wire, so verification happens before any decompression.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from datetime import datetime, timezone

SKEW_SECONDS = 300  # requests must be within five minutes of gateway time


def body_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build_signing_text(
    method: str,
    path: str,
    station: str,
    key_id: str,
    timestamp: str,
    nonce: str,
    raw_body: bytes,
) -> bytes:
    lines = [
        method.upper(),
        path,
        station,
        key_id,
        timestamp,
        nonce,
        body_digest(raw_body),
    ]
    return "\n".join(lines).encode("utf-8")


def compute_signature(secret: bytes, signing_text: bytes) -> str:
    digest = hmac.new(secret, signing_text, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def verify_signature(secret: bytes, signing_text: bytes, provided: str) -> bool:
    try:
        provided_bytes = base64.b64decode(provided, validate=True)
    except (binascii.Error, ValueError):
        return False
    expected = hmac.new(secret, signing_text, hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided_bytes)


def parse_timestamp(raw: str) -> datetime:
    """Parse X-Timestamp: Unix epoch seconds or ISO-8601 (``Z`` allowed)."""
    text = raw.strip()
    if text and text.lstrip("-").replace(".", "", 1).isdigit():
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    iso = text[:-1] + "+00:00" if text.endswith("Z") else text
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def within_skew(sent_at: datetime, now: datetime, max_skew: int = SKEW_SECONDS) -> bool:
    return abs((now - sent_at).total_seconds()) <= max_skew
