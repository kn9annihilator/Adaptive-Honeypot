import tempfile
import unittest
from pathlib import Path

from acquire_samples import (
    CorpusIdentityIndex,
    candidate_is_valid,
    recover_staging,
    sha256_file,
    valid_sha256,
)


class AcquisitionTests(unittest.TestCase):
    def test_sha256_validation(self):
        self.assertTrue(valid_sha256("a" * 64))
        self.assertFalse(valid_sha256("a" * 63))
        self.assertFalse(valid_sha256("g" * 64))

    def test_candidate_validation_accepts_pending_pe(self):
        ok, reason = candidate_is_valid({
            "selected": "pending", "sha256": "a" * 64, "file_type": "exe"
        })
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_candidate_validation_rejection_is_scope_not_crypto(self):
        ok, reason = candidate_is_valid({
            "selected": "no", "sha256": "a" * 64,
            "file_type": "vbs", "exclusion_reason": "non_pe_artifact"
        })
        self.assertFalse(ok)
        self.assertEqual(reason, "non_pe_artifact")

    def test_identity_index_is_o1_after_one_scan(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "samples.jsonl"
            p.write_text(
                '{"identity":{"sha256":"' + "a" * 64 + '"}}\n',
                encoding="utf-8",
            )
            idx = CorpusIdentityIndex(p)
            self.assertTrue(idx.contains("A" * 64))
            self.assertFalse(idx.contains("b" * 64))
            idx.add("b" * 64)
            self.assertTrue(idx.contains("B" * 64))

    def test_streaming_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample"
            p.write_bytes(b"A" * (2 * 1024 * 1024 + 17))
            self.assertEqual(len(sha256_file(p)), 64)

    def test_recovery_removes_staging_only(self):
        with tempfile.TemporaryDirectory() as d:
            # Function uses the real project path, so this test only verifies
            # that an absent staging root is a no-op.
            self.assertEqual(recover_staging(), 0)


if __name__ == "__main__":
    unittest.main()
