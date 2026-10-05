"""HTTP smoke checks executed against a running gateway.

Covers the requirements that are only observable end-to-end:
  * correct HMAC signing over raw on-wire bytes (plain + gzip)
  * compression round-trip
  * anti-replay: duplicate nonce and a concurrent burst with one nonce
  * distinct failure codes for each rejection reason
  * failed requests never reserve a nonce
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.config import load_keys
from app.signing import build_signing_text, compute_signature

EVENTS_PATH = "/api/telemetry/events"


class SmokeFailure(Exception):
    pass


def _post(base_url: str, body: bytes, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(base_url + EVENTS_PATH, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _event(eid: str, dose: float = 0.37, station: str = "ST01") -> dict:
    return {
        "event_id": eid,
        "station": station,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "dose_uSv": dose,
    }


def _headers_for(
    keys,
    raw_body: bytes,
    nonce: str,
    station: str = "ST01",
    key_id: str = "k1",
    timestamp: str | None = None,
    gzipped: bool = False,
    signature: str | None = None,
) -> dict[str, str]:
    key = keys[(station, key_id)]
    ts = timestamp or str(int(time.time()))
    if signature is None:
        text = build_signing_text("POST", EVENTS_PATH, station, key_id, ts, nonce, raw_body)
        signature = compute_signature(key.secret, text)
    headers = {
        "Content-Type": "application/json",
        "X-Station": station,
        "X-Key-Id": key_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": signature,
    }
    if gzipped:
        headers["Content-Encoding"] = "gzip"
    return headers


def run(base_url: str, keys_file: str | None = None) -> None:
    keys = load_keys(keys_file)
    print(f"[smoke] target: {base_url}")

    # 1. Signed plain JSON -> 202 + stable digest; repeat transport yields same digest
    event = _event("smoke-evt-0001")
    plain = json.dumps(event).encode("utf-8")
    status, payload = _post(base_url, plain, _headers_for(keys, plain, nonce="smoke-n-0001"))
    _expect("plain JSON accepted", status, payload, 202)
    digest_a = payload["digest"]
    _assert_eq(len(digest_a), 64, "digest is 64 hex chars")

    # 2. Gzip signed over compressed bytes -> 202, same stable digest
    compressed = gzip.compress(plain)
    status, payload = _post(
        base_url, compressed, _headers_for(keys, compressed, nonce="smoke-n-0002", gzipped=True)
    )
    _expect("gzip JSON accepted", status, payload, 202)
    _assert_eq(payload["digest"], digest_a, "gzip preserves stable digest")

    # 3. Replay identical request -> 409 duplicate_nonce
    status, payload = _post(base_url, plain, _headers_for(keys, plain, nonce="smoke-n-0001"))
    _expect_code("sequential replay", status, payload, 409, "duplicate_nonce")

    # 4. Concurrent burst sharing one nonce -> exactly one 202, rest 409
    burst_body = json.dumps(_event("smoke-evt-burst", 1.25)).encode()
    burst_headers = _headers_for(keys, burst_body, nonce="smoke-n-burst")

    def fire(_):
        return _post(base_url, burst_body, burst_headers)

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(fire, range(20)))
    wins = [r for r in results if r[0] == 202]
    dups = [r for r in results if r[1].get("error") == "duplicate_nonce"]
    _assert_eq(len(wins), 1, f"concurrent burst: exactly one accept (got {len(wins)})")
    _assert_eq(len(dups), 19, f"concurrent burst: 19 duplicates (got {len(dups)})")

    # 5. Distinct failure codes
    bad_sig_headers = _headers_for(
        keys, plain, nonce="smoke-n-badsig", signature=base64.b64encode(b"\x00" * 32).decode()
    )
    _expect_code("bad signature", *_post(base_url, plain, bad_sig_headers), 401, "invalid_signature")

    expired = json.dumps(_event("smoke-evt-exp", station="ST03")).encode()
    expired_headers = _headers_for(keys, expired, nonce="smoke-n-exp", station="ST03", key_id="key-expired")
    _expect_code("expired key", *_post(base_url, expired, headers=expired_headers), 403, "expired_key")

    old_headers = _headers_for(keys, plain, nonce="smoke-n-old", timestamp=str(int(time.time()) - 600))
    _expect_code("time out of bounds", *_post(base_url, plain, old_headers), 440, "time_out_of_bounds")

    garbage = b"{oops"
    _expect_code(
        "malformed payload",
        *_post(base_url, garbage, _headers_for(keys, garbage, nonce="smoke-n-garbage")),
        422,
        "malformed_json",
    )

    bad_gzip = b"\x1f\x8bxxxx"
    _expect_code(
        "invalid gzip",
        *_post(base_url, bad_gzip, _headers_for(keys, bad_gzip, nonce="smoke-n-badgz", gzipped=True)),
        415,
        "invalid_gzip",
    )

    # 6. A rejected request must not consume its nonce
    recover = json.dumps(_event("smoke-evt-recover")).encode()
    bad = _headers_for(
        keys, recover, nonce="smoke-n-recover", signature=base64.b64encode(b"\x01" * 32).decode()
    )
    _expect_code("pre-failure rejection", *_post(base_url, recover, bad), 401, "invalid_signature")
    good = _headers_for(keys, recover, nonce="smoke-n-recover")
    _expect("nonce reusable after rejection", *_post(base_url, recover, good), 202)
    _expect_code("then locked", *_post(base_url, recover, good), 409, "duplicate_nonce")

    print("[smoke] all smoke checks passed")


def _expect(label: str, status: int, payload: dict, expected: int) -> None:
    if status != expected:
        raise SmokeFailure(f"{label}: expected {expected}, got {status}: {payload}")
    print(f"[smoke] ok - {label} ({status})")


def _expect_code(label: str, status: int, payload: dict, exp_status: int, exp_code: str) -> None:
    if status != exp_status or payload.get("error") != exp_code:
        raise SmokeFailure(
            f"{label}: expected {exp_status}/{exp_code}, got {status}/{payload.get('error')}: {payload}"
        )
    print(f"[smoke] ok - {label} ({status} {exp_code})")


def _assert_eq(actual, expected, label: str) -> None:
    if actual != expected:
        raise SmokeFailure(f"{label}: expected {expected!r}, got {actual!r}")
