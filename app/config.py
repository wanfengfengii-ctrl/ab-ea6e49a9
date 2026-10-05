"""Configuration loading for the telemetry gateway.

Keys are described in a JSON file (path override with TELEMETRY_KEYS_FILE).
Each key entry::

    {
      "station": "ST01",
      "key_id": "k1",
      "secret":   "base64-encoded HMAC secret",   # or "secret_hex"
      "not_before": "2024-01-01T00:00:00Z",        # optional
      "not_after":  "2030-12-31T23:59:59Z"         # optional
    }

Times accept an explicit ``Z``/offset suffix, or are treated as UTC when
the string carries no timezone.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_KEYS_FILE = Path(__file__).resolve().parent.parent / "config" / "keys.json"


@dataclass(frozen=True)
class StationKey:
    station: str
    key_id: str
    secret: bytes
    not_before: datetime | None
    not_after: datetime | None

    def valid_at(self, moment: datetime) -> bool:
        if self.not_before is not None and moment < self.not_before:
            return False
        if self.not_after is not None and moment > self.not_after:
            return False
        return True


def parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _decode_secret(entry: dict) -> bytes:
    if "secret" in entry:
        return base64.b64decode(entry["secret"], validate=True)
    if "secret_hex" in entry:
        return bytes.fromhex(entry["secret_hex"])
    raise ValueError("key entry requires 'secret' (base64) or 'secret_hex'")


def load_keys(path: str | os.PathLike[str] | None = None) -> dict[tuple[str, str], StationKey]:
    """Return registered keys indexed by ``(station, key_id)``."""
    keys_path = Path(path) if path else Path(os.environ.get("TELEMETRY_KEYS_FILE", DEFAULT_KEYS_FILE))
    with keys_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if isinstance(raw, dict) and "keys" in raw:
        raw = raw["keys"]
    keys: dict[tuple[str, str], StationKey] = {}
    for entry in raw:
        station = str(entry["station"])
        key_id = str(entry["key_id"])
        try:
            secret = _decode_secret(entry)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"invalid secret for {station}/{key_id}: {exc}") from exc
        keys[(station, key_id)] = StationKey(
            station=station,
            key_id=key_id,
            secret=secret,
            not_before=parse_time(entry.get("not_before")),
            not_after=parse_time(entry.get("not_after")),
        )
    if not keys:
        raise ValueError("no station keys configured")
    return keys
