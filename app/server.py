"""HTTP gateway for dose-event telemetry.

Request processing order (the first failing stage wins, and only a fully
valid, accepted request reserves a nonce):

1. required headers present
2. station/key registered
3. key within its validity window
4. timestamp parseable and within five minutes of gateway time
5. HMAC signature verified over the *raw* body bytes
6. gzip decompression (when declared)
7. JSON parsing and event validation
8. atomic nonce claim (replay rejected, survives restarts)
"""

from __future__ import annotations

import json
import os
import threading
import zlib
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import StationKey, load_keys
from .events import EventValidationError, canonical_digest, validate_event
from .nonce_store import NonceReplayed, NonceStore
from .signing import (
    SKEW_SECONDS,
    build_signing_text,
    parse_timestamp,
    verify_signature,
    within_skew,
)

EVENTS_PATH = "/api/telemetry/events"
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_NONCE_LEN = 128


class Gateway:
    def __init__(self, keys, nonce_store: NonceStore):
        self.keys = keys
        self.nonces = nonce_store
        self.received_count = 0
        self._counter_lock = threading.Lock()

    def next_seq(self) -> int:
        with self._counter_lock:
            self.received_count += 1
            return self.received_count


class RequestError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _gunzip_limited(raw: bytes, max_output: int) -> bytes | None:
    """Streaming gunzip with a decompressed-size cap (gzip-bomb guard).

    Returns ``None`` for truncated/corrupt streams (including CRC or size
    footer mismatches).
    """
    decomp = zlib.decompressobj(wbits=31)  # 31 = gzip framing
    chunks: list[bytes] = []
    total = 0
    pending = raw
    try:
        while pending:
            piece = decomp.decompress(pending, max_output - total + 1)
            chunks.append(piece)
            total += len(piece)
            if total > max_output:
                raise RequestError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    "payload_too_large",
                    "decompressed body exceeds limit",
                )
            pending = decomp.unconsumed_tail
        chunks.append(decomp.flush())
        total += len(chunks[-1])
        if total > max_output:
            raise RequestError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "payload_too_large",
                "decompressed body exceeds limit",
            )
        if not decomp.eof:  # truncated gzip stream
            return None
    except zlib.error:
        return None
    return b"".join(chunks)


def handle_event(gateway: Gateway, headers, raw_body: bytes) -> tuple[int, dict]:
    station = headers.get("X-Station")
    key_id = headers.get("X-Key-Id")
    timestamp_raw = headers.get("X-Timestamp")
    nonce = headers.get("X-Nonce")
    signature = headers.get("X-Signature")

    if not all([station, key_id, timestamp_raw, nonce, signature]):
        raise RequestError(
            HTTPStatus.UNAUTHORIZED,
            "missing_auth_headers",
            "X-Station, X-Key-Id, X-Timestamp, X-Nonce and X-Signature are required",
        )

    if len(nonce) > MAX_NONCE_LEN or not nonce.strip():
        raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_nonce", "nonce must be 1..128 characters")

    key: StationKey | None = gateway.keys.get((station, key_id))
    if key is None:
        raise RequestError(HTTPStatus.UNAUTHORIZED, "unknown_key", "station/key_id is not registered")

    now = _now()

    if not key.valid_at(now):
        if key.not_before is not None and now < key.not_before:
            raise RequestError(HTTPStatus.FORBIDDEN, "key_not_yet_valid", "key is not active yet")
        raise RequestError(HTTPStatus.FORBIDDEN, "expired_key", "key has expired")

    try:
        sent_at = parse_timestamp(timestamp_raw)
    except (ValueError, OverflowError):
        raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_timestamp", "timestamp is not parseable")
    if not within_skew(sent_at, now):
        raise RequestError(
            440,  # non-standard but explicit: Login Timeout-style "time out of bounds"
            "time_out_of_bounds",
            f"timestamp differs from gateway time by more than {SKEW_SECONDS} seconds",
        )

    signing_text = build_signing_text(
        "POST", EVENTS_PATH, station, key_id, timestamp_raw, nonce, raw_body
    )
    if not verify_signature(key.secret, signing_text, signature):
        raise RequestError(HTTPStatus.UNAUTHORIZED, "invalid_signature", "HMAC verification failed")

    encoding = (headers.get("Content-Encoding") or "identity").strip().lower()
    if encoding == "gzip":
        body = _gunzip_limited(raw_body, MAX_BODY_BYTES)
        if body is None:
            raise RequestError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "invalid_gzip", "body is not valid gzip")
    elif encoding in ("", "identity"):
        body = raw_body
    else:
        raise RequestError(
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
            "unsupported_encoding",
            f"content encoding {encoding!r} is not supported",
        )

    if len(body) > MAX_BODY_BYTES:
        raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "payload_too_large", "event body exceeds limit")

    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "malformed_json", "body is not valid JSON")

    try:
        event = validate_event(data, station)
    except EventValidationError as exc:
        raise RequestError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_event", str(exc))

    digest = canonical_digest(event)
    try:
        gateway.nonces.claim(station, nonce, now.isoformat(), digest)
    except NonceReplayed:
        raise RequestError(HTTPStatus.CONFLICT, "duplicate_nonce", "this station nonce was already accepted")

    seq = gateway.next_seq()
    return HTTPStatus.ACCEPTED, {
        "status": "accepted",
        "event_id": event["event_id"],
        "station": station,
        "received_seq": seq,
        "received_at": now.isoformat(),
        "digest": digest,
    }


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "TelemetryGateway/1.0"
    gateway: Gateway  # injected on the server instance

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, err: RequestError) -> None:
        self._send_json(err.status, {"status": "rejected", "error": err.code, "message": err.message})

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"status": "rejected", "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path != EVENTS_PATH:
            self._send_json(HTTPStatus.NOT_FOUND, {"status": "rejected", "error": "not_found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._fail(RequestError(HTTPStatus.LENGTH_REQUIRED, "length_required", "invalid Content-Length"))
            return
        if length <= 0:
            self._fail(RequestError(HTTPStatus.BAD_REQUEST, "empty_body", "request body is empty"))
            return
        if length > MAX_BODY_BYTES:
            self._fail(RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "payload_too_large", "body exceeds limit"))
            return

        raw_body = self.rfile.read(length)

        try:
            status, payload = handle_event(self.server.gateway, self.headers, raw_body)
            self._send_json(status, payload)
        except RequestError as err:
            self._fail(err)

    def log_message(self, fmt: str, *args) -> None:  # quieter, structured logs
        ts = _now().isoformat()
        print(f"{ts} {self.address_string()} {fmt % args}", flush=True)


def build_server(host: str, port: int, keys_file: str | None, db_path: str) -> tuple[ThreadingHTTPServer, NonceStore]:
    keys = load_keys(keys_file)
    store = NonceStore(db_path)
    gateway = Gateway(keys, store)
    server = ThreadingHTTPServer((host, port), GatewayHandler)
    server.gateway = gateway
    return server, store


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("TELEMETRY_DB", "/data/nonces.db")
    keys_file = os.environ.get("TELEMETRY_KEYS_FILE")
    server, store = build_server(host, port, keys_file, db_path)
    print(f"telemetry gateway listening on {host}:{port}, db={db_path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()


if __name__ == "__main__":
    main()
