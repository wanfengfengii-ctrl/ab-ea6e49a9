import os
import tempfile
import threading
import unittest

from app.nonce_store import NonceReplayed, NonceStore


class NonceStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self._tmp.name, "nonces.db")

    def tearDown(self):
        self._tmp.cleanup()

    def test_claim_then_replay_rejected(self):
        store = NonceStore(self.db)
        store.claim("ST01", "n1", "2026-10-05T00:00:00Z", "hash1")
        self.assertTrue(store.is_used("ST01", "n1"))
        with self.assertRaises(NonceReplayed):
            store.claim("ST01", "n1", "2026-10-05T00:00:01Z", "hash2")

    def test_nonce_scoped_per_station(self):
        store = NonceStore(self.db)
        store.claim("ST01", "shared", "t", None)
        store.claim("ST02", "shared", "t", None)  # must not raise
        self.assertTrue(store.is_used("ST01", "shared"))
        self.assertTrue(store.is_used("ST02", "shared"))

    def test_nonce_persists_across_restart(self):
        NonceStore(self.db).claim("ST01", "persist-me", "t", None)
        reopened = NonceStore(self.db)  # simulates gateway restart
        with self.assertRaises(NonceReplayed):
            reopened.claim("ST01", "persist-me", "t2", None)

    def test_concurrent_claims_exactly_one_wins(self):
        store = NonceStore(self.db)
        winners: list[int] = []
        failures: list[int] = []
        barrier = threading.Barrier(16)

        def attempt():
            barrier.wait()
            try:
                store.claim("ST01", "race-nonce", "t", None)
                winners.append(threading.get_ident())
            except NonceReplayed:
                failures.append(threading.get_ident())

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(winners), 1)
        self.assertEqual(len(failures), 15)


if __name__ == "__main__":
    unittest.main()
