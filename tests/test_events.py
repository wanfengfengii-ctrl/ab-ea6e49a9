import gzip
import json
import unittest

from app.events import EventValidationError, canonical_digest, validate_event


class EventTests(unittest.TestCase):
    def test_digest_stable_across_key_order_and_whitespace(self):
        a = {"event_id": "e1", "dose_uSv": 1.5, "measured_at": "2026-10-05T00:00:00Z"}
        reordered = {"measured_at": "2026-10-05T00:00:00Z", "dose_uSv": 1.5, "event_id": "e1"}
        self.assertEqual(canonical_digest(a), canonical_digest(reordered))
        roundtripped = json.loads(json.dumps(a, indent=2))
        self.assertEqual(canonical_digest(a), canonical_digest(roundtripped))

    def test_digest_independent_of_gzip_transport(self):
        event = {"event_id": "e1", "measured_at": "2026-10-05T00:00:00Z", "dose_uSv": 2}
        plain = json.dumps(event).encode()
        after_gzip = json.loads(gzip.decompress(gzip.compress(plain)))
        self.assertEqual(canonical_digest(after_gzip), canonical_digest(event))

    def test_valid_event_passes(self):
        event = {"event_id": "e1", "measured_at": "2026-10-05T00:00:00Z", "dose_uSv": 3.14}
        self.assertEqual(validate_event(event, "ST01")["event_id"], "e1")

    def test_station_mismatch_rejected(self):
        with self.assertRaisesRegex(EventValidationError, "station"):
            validate_event(
                {"event_id": "e1", "measured_at": "2026-10-05T00:00:00Z", "dose_uSv": 1, "station": "ST09"},
                "ST01",
            )

    def test_invalid_events_rejected(self):
        bad_events = [
            {"event_id": "", "measured_at": "2026-10-05T00:00:00Z", "dose_uSv": 1},
            {"event_id": "e1", "measured_at": "not-a-time", "dose_uSv": 1},
            {"event_id": "e1", "measured_at": "2026-10-05T00:00:00Z"},  # missing dose
            {"event_id": "e1", "measured_at": "2026-10-05T00:00:00Z", "dose_uSv": -1},
            {"event_id": "e1", "measured_at": "2026-10-05T00:00:00Z", "dose_uSv": "nan"},
            {"event_id": "e1", "measured_at": "2026-10-05T00:00:00Z", "dose_uSv": True},
            [1, 2, 3],
            "not-an-object",
        ]
        for event in bad_events:
            with self.subTest(event=event):
                with self.assertRaises(EventValidationError):
                    validate_event(event, "ST01")


if __name__ == "__main__":
    unittest.main()
