import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from acquire_samples import (
    CorpusIdentityIndex,
    candidate_is_valid,
    extract_sample,
    reconcile_corpus,
    sha256_file,
    valid_sha256,
)


class AcquisitionV3Tests(unittest.TestCase):
    def test_sha256_validation(self):
        self.assertTrue(valid_sha256("a" * 64))
        self.assertFalse(valid_sha256("a" * 63))
        self.assertFalse(valid_sha256("g" * 64))

    def test_candidate_validation_boundary(self):
        ok, reason = candidate_is_valid({
            "selected": "no",
            "sha256": "a" * 64,
            "file_type": "vbs",
            "exclusion_reason": "non_pe_artifact",
        })
        self.assertFalse(ok)
        self.assertEqual(reason, "non_pe_artifact")

    def test_identity_index_single_scan_membership(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "samples.jsonl"
            p.write_text('{"identity":{"sha256":"' + "a" * 64 + '"}}\n', encoding="utf-8")
            idx = CorpusIdentityIndex(p)
            self.assertTrue(idx.contains("A" * 64))
            self.assertFalse(idx.contains("b" * 64))

    def test_stats_print_supports_slots(self):
        import io
        from contextlib import redirect_stdout
        from acquire_samples import AcquisitionStats
        buf = io.StringIO()
        with redirect_stdout(buf):
            AcquisitionStats(queued=1).print()
        self.assertIn("Queued: 1", buf.getvalue())

    def test_streaming_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample"
            p.write_bytes(b"A" * (2 * 1024 * 1024 + 17))
            self.assertEqual(
                sha256_file(p),
                hashlib.sha256(p.read_bytes()).hexdigest(),
            )

    def test_aes_zip_extraction_is_streamed(self):
        pyzipper = __import__("pyzipper")
        payload = b"synthetic malware corpus test payload" * 100
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "sample.zip"
            output = root / "extracted" / "sample"
            with pyzipper.AESZipFile(
                archive, "w", compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(b"infected")
                zf.writestr("original.exe", payload)
            member = extract_sample(archive, output)
            self.assertEqual(member, "original.exe")
            self.assertEqual(output.read_bytes(), payload)

    def test_multiple_archive_members_are_rejected(self):
        pyzipper = __import__("pyzipper")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "multi.zip"
            output = root / "sample"
            with pyzipper.AESZipFile(
                archive, "w", compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(b"infected")
                zf.writestr("a.exe", b"a")
                zf.writestr("b.exe", b"b")
            with self.assertRaises(ValueError):
                extract_sample(archive, output)

    def test_reconcile_detects_orphan_and_missing(self):
        import acquire_samples as a
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest = root / "samples.jsonl"
            quarantine = root / "quarantine"
            quarantine.mkdir()
            h1, h2 = "a" * 64, "b" * 64
            (quarantine / h1).mkdir()
            (quarantine / h1 / "sample").write_bytes(b"x")
            manifest.write_text(
                '{"identity":{"sha256":"' + h2 + '"}}\n',
                encoding="utf-8",
            )
            with mock.patch.object(a, "SAMPLES_MANIFEST", manifest), \
                 mock.patch.object(a, "QUARANTINE_ROOT", quarantine):
                orphan, missing = reconcile_corpus()
            self.assertEqual(orphan, [h1])
            self.assertEqual(missing, [h2])


if __name__ == "__main__":
    unittest.main()
