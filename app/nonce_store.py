"""Persistent nonce replay protection.

A single SQLite table records nonces that were part of a *successfully
accepted* request, keyed by ``(station, nonce)``. The unique index plus an
immediate transaction makes the claim atomic: under concurrency exactly one
request for the same nonce can commit; the loser gets :class:`NonceReplayed`
and remains free to roll back without reserving the nonce.

The database survives process restarts, so a captured-and-replayed event is
still rejected after the gateway restarts.
"""

from __future__ import annotations

import sqlite3
import threading


class NonceReplayed(Exception):
    """Raised when a station reuses a nonce that already succeeded once."""


class NonceStore:
    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS used_nonces (
                station    TEXT NOT NULL,
                nonce      TEXT NOT NULL,
                seen_at    TEXT NOT NULL,
                event_hash TEXT,
                PRIMARY KEY (station, nonce)
            )
            """
        )

    def claim(self, station: str, nonce: str, seen_at: str, event_hash: str | None) -> None:
        """Atomically reserve ``nonce`` for ``station``.

        Raises :class:`NonceReplayed` if the nonce was already committed.
        On any other failure the transaction is rolled back, so the nonce
        stays unreserved (a failed request never consumes a nonce).
        """
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                cur = self._conn.execute(
                    "SELECT 1 FROM used_nonces WHERE station = ? AND nonce = ?",
                    (station, nonce),
                )
                if cur.fetchone() is not None:
                    self._conn.execute("ROLLBACK")
                    raise NonceReplayed(station, nonce)
                self._conn.execute(
                    "INSERT INTO used_nonces (station, nonce, seen_at, event_hash) VALUES (?, ?, ?, ?)",
                    (station, nonce, seen_at, event_hash),
                )
                self._conn.execute("COMMIT")
            except NonceReplayed:
                raise
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def is_used(self, station: str, nonce: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM used_nonces WHERE station = ? AND nonce = ?",
                (station, nonce),
            )
            return cur.fetchone() is not None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
