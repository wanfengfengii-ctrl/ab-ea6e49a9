"""End-to-end tests over a real HTTP listener on an ephemeral port."""

from __future__ import annotations

import base64
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from app.server import build_server
from tests.helpers import KEYS, encode_body, make_event, signed_headers

BASE_URL = ""
_httpd = None
_nonce_seq = 0


def _next_nonce(prefix: str) -> str:
    global _nonce_seq
    _nonce_seq += 1
    return f"{prefix}-{_nonce_seq}"


def setUpModule():
    global BASE_URL, _httpd
    tmp = tempfile.mkdtemp(prefix="telemetry-e2e-")
    db = f"{tmp}/nonces.db"
    _httpd, _store = build_server("127.0.0.1", 0, "config/keys.json", db)
    thread = threading.Thread(target=_httpd.serve_forever, daemon=True)
    thread.start()
    host, port = _httpd.server_address
    BASE_URL = f"http://{host}:{port}"


def tearDownModule():
    _httpd.shutdown()
    _httpd.server_close()


def post(body: bytes, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(BASE_URL + "/api/telemetry/events", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class GatewayE2ETests(unittest.TestCase):
    def test_health(self):
        with urllib.request.urlopen(BASE_URL + "/healthz", timeout=5) as resp:
            self.assertEqual(resp.status, 200)

    def test_accept_plain_json_returns_202_and_stable_digest(self):
        event = make_event(event_id="evt-accept-1")
        body = encode_body(event)
        status, payload = post(body, signed_headers(body, nonce=_next_nonce("n-accept")))
        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "accepted")
        self.assertEqual(payload["event_id"], "evt-accept-1")
        self.assertEqual(len(payload["digest"]), 64)

        # same content, different nonce -> identical stable digest
        body2 = encode_body(event)
        status2, payload2 = post(body2, signed_headers(body2, nonce=_next_nonce("n-accept")))
        self.assertEqual(status2, 202)
        self.assertEqual(payload2["digest"], payload["digest"])

    def test_accept_gzip_json(self):
        event = make_event(event_id="evt-gzip-1")
        body = encode_body(event, gzipped=True)
        status, payload = post(body, signed_headers(body, nonce=_next_nonce("n-gzip"), gzipped=True))
        self.assertEqual(status, 202)
        self.assertTrue(payload["digest"])

    def test_missing_headers(self):
        status, payload = post(b"{}", {"Content-Type": "application/json"})
        self.assertEqual((status, payload["error"]), (401, "missing_auth_headers"))

    def test_unknown_key(self):
        event = make_event()
        body = encode_body(event)
        headers = signed_headers(body, station="ST01", key_id="nope", secret=b"x", nonce=_next_nonce("n-unk"))
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (401, "unknown_key"))

    def test_expired_key_distinct_code(self):
        event = make_event(station="ST03")
        body = encode_body(event)
        headers = signed_headers(body, station="ST03", key_id="key-expired", nonce=_next_nonce("n-exp"))
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (403, "expired_key"))

    def test_time_out_of_bounds_distinct_code(self):
        event = make_event()
        body = encode_body(event)
        old_ts = str(int(time.time()) - 600)
        headers = signed_headers(body, timestamp=old_ts, nonce=_next_nonce("n-old"))
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (440, "time_out_of_bounds"))

    def test_bad_timestamp_format(self):
        event = make_event()
        body = encode_body(event)
        headers = signed_headers(body, timestamp="yesterday", nonce=_next_nonce("n-badts"))
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (400, "invalid_timestamp"))

    def test_invalid_signature_distinct_code(self):
        event = make_event()
        body = encode_body(event)
        headers = signed_headers(body, nonce=_next_nonce("n-sig"))
        raw_sig = base64.b64decode(headers["X-Signature"])
        headers["X-Signature"] = base64.b64encode(bytes([raw_sig[0] ^ 0xFF]) + raw_sig[1:]).decode()
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (401, "invalid_signature"))

    def test_signature_covers_raw_body_tampering(self):
        event = make_event()
        body = encode_body(event)
        headers = signed_headers(body, nonce=_next_nonce("n-tamper"))
        tampered = body.replace(b"0.37", b"99.9")
        self.assertNotEqual(tampered, body)
        status, payload = post(tampered, headers)
        self.assertEqual((status, payload["error"]), (401, "invalid_signature"))

    def test_decompress_failure_distinct_code(self):
        bad_gzip = b"\x1f\x8bnotreallygzip"
        # sign the actual on-wire bytes so HMAC passes and decompression is reached
        headers = signed_headers(bad_gzip, nonce=_next_nonce("n-badgz"), gzipped=True)
        status, payload = post(bad_gzip, headers)
        self.assertEqual((status, payload["error"]), (415, "invalid_gzip"))

    def test_gzip_bomb_rejected_and_nonce_free(self):
        import gzip as _gzip

        huge = b'{"event_id":"big","measured_at":"2026-10-05T00:00:00Z","dose_uSv":1,"pad":"' \
            + b"0" * (3 * 1024 * 1024) + b'"}'
        compressed = _gzip.compress(huge)
        self.assertLess(len(compressed), 100_000)
        headers = signed_headers(compressed, nonce="n-fixed-bomb", gzipped=True)
        status, payload = post(compressed, headers)
        self.assertEqual(status, 413)
        self.assertEqual(payload["error"], "payload_too_large")
        # rejected bomb must not reserve its nonce: a small event with it is accepted
        body = encode_body(make_event(event_id="evt-bomb-nonce-reuse"))
        status, _ = post(body, signed_headers(body, nonce="n-fixed-bomb"))
        self.assertEqual(status, 202)

    def test_malformed_json_distinct_code(self):
        body = b"{not json"
        headers = signed_headers(body, nonce=_next_nonce("n-json"))
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (422, "malformed_json"))

    def test_invalid_event_distinct_code(self):
        body = encode_body({"event_id": "x", "measured_at": "2026-10-05T00:00:00Z"})  # no dose
        headers = signed_headers(body, nonce=_next_nonce("n-invevt"))
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (422, "invalid_event"))

    def test_duplicate_nonce_distinct_code(self):
        event = make_event(event_id="evt-dup")
        body = encode_body(event)
        headers = signed_headers(body, nonce="n-fixed-dup")
        self.assertEqual(post(body, headers)[0], 202)
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (409, "duplicate_nonce"))

    def test_failed_request_does_not_consume_nonce(self):
        nonce = "n-fixed-recover-after-fail"
        event = make_event(event_id="evt-recover")
        body = encode_body(event)

        bad_headers = signed_headers(body, nonce=nonce)
        bad_headers["X-Signature"] = base64.b64encode(b"\x00" * 32).decode()
        status, _ = post(body, bad_headers)
        self.assertEqual(status, 401)

        # same nonce, valid signature -> must still succeed exactly once
        good_headers = signed_headers(body, nonce=nonce)
        self.assertEqual(post(body, good_headers)[0], 202)
        self.assertEqual(post(body, good_headers)[0], 409)

    def test_concurrent_requests_same_nonce_exactly_one_accepted(self):
        event = make_event(event_id="evt-concurrent")
        body = encode_body(event)
        headers = signed_headers(body, nonce="n-fixed-concurrent-race")

        def fire(_):
            return post(body, headers)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(fire, range(16)))

        accepted = [r for r in results if r[0] == 202]
        rejected = [r for r in results if r[1].get("error") == "duplicate_nonce"]
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(rejected), 15)

    def test_wrong_station_secret_rejected(self):
        event = make_event()
        body = encode_body(event)
        headers = signed_headers(
            body, station="ST01", key_id="k1", secret=KEYS[("ST02", "k1")], nonce=_next_nonce("n-cross")
        )
        status, payload = post(body, headers)
        self.assertEqual((status, payload["error"]), (401, "invalid_signature"))


if __name__ == "__main__":
    unittest.main()
