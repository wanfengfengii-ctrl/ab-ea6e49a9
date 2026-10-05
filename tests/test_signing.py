import gzip
import unittest
from datetime import datetime, timedelta, timezone

from app.signing import (
    SKEW_SECONDS,
    body_digest,
    build_signing_text,
    compute_signature,
    parse_timestamp,
    verify_signature,
    within_skew,
)

SECRET = b"topsecret"


class SigningTests(unittest.TestCase):
    def test_body_digest_is_sha256_hex_of_raw_bytes(self):
        self.assertEqual(
            body_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_signing_text_field_order_and_newlines(self):
        text = build_signing_text("post", "/p", "S", "k", "12", "n1", b"abc")
        self.assertEqual(text, b"POST\n/p\nS\nk\n12\nn1\n" + body_digest(b"abc").encode())

    def test_valid_signature_roundtrip(self):
        text = build_signing_text("POST", "/p", "S", "k", "12", "n1", b"abc")
        sig = compute_signature(SECRET, text)
        self.assertTrue(verify_signature(SECRET, text, sig))
        text2 = build_signing_text("POST", "/p", "S", "k", "12", "n1", b"abd")
        self.assertFalse(verify_signature(SECRET, text2, sig))

    def test_signature_binds_every_field(self):
        text = build_signing_text("POST", "/p", "S", "k", "12", "n1", b"abc")
        sig = compute_signature(SECRET, text)
        tampered = [
            build_signing_text("GET", "/p", "S", "k", "12", "n1", b"abc"),
            build_signing_text("POST", "/q", "S", "k", "12", "n1", b"abc"),
            build_signing_text("POST", "/p", "T", "k", "12", "n1", b"abc"),
            build_signing_text("POST", "/p", "S", "x", "12", "n1", b"abc"),
            build_signing_text("POST", "/p", "S", "k", "13", "n1", b"abc"),
            build_signing_text("POST", "/p", "S", "k", "12", "n2", b"abc"),
        ]
        for candidate in tampered:
            self.assertFalse(verify_signature(SECRET, candidate, sig))

    def test_wrong_secret_fails(self):
        text = build_signing_text("POST", "/p", "S", "k", "12", "n1", b"abc")
        sig = compute_signature(b"other", text)
        self.assertFalse(verify_signature(SECRET, text, sig))

    def test_malformed_base64_signature_rejected(self):
        text = build_signing_text("POST", "/p", "S", "k", "12", "n1", b"abc")
        self.assertFalse(verify_signature(SECRET, text, "not base64!!!"))
        self.assertFalse(verify_signature(SECRET, text, ""))

    def test_parse_timestamp_epoch_and_iso(self):
        self.assertEqual(
            parse_timestamp("1700000000"),
            datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc),
        )
        self.assertEqual(parse_timestamp("2025-01-01T00:00:00Z"), datetime(2025, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(
            parse_timestamp("2025-01-01T02:00:00+02:00"),
            datetime(2025, 1, 1, tzinfo=timezone.utc),
        )

    def test_skew_boundary_is_inclusive(self):
        now = datetime.now(timezone.utc)
        self.assertTrue(within_skew(now + timedelta(seconds=SKEW_SECONDS), now))
        self.assertTrue(within_skew(now - timedelta(seconds=SKEW_SECONDS), now))
        self.assertFalse(within_skew(now + timedelta(seconds=SKEW_SECONDS + 1), now))
        self.assertFalse(within_skew(now - timedelta(seconds=SKEW_SECONDS + 1), now))

    def test_gzip_bytes_have_distinct_digest_from_plaintext(self):
        self.assertNotEqual(body_digest(gzip.compress(b"abc")), body_digest(b"abc"))


if __name__ == "__main__":
    unittest.main()
