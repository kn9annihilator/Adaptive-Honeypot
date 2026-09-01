import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED

import acquire_samples


class AcquisitionV32Tests(unittest.TestCase):

    def test_sha256_streaming(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"

            data = b"A" * (2 * 1024 * 1024)

            path.write_bytes(data)

            expected = hashlib.sha256(
                data
            ).hexdigest()

            self.assertEqual(
                acquire_samples.sha256_file(path),
                expected,
            )

    def test_sha256_validation(self):
        expected = "a" * 64

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample"

            path.write_bytes(
                b"test-data"
            )

            with self.assertRaises(ValueError):
                acquire_samples.verify_hash(
                    path,
                    expected,
                )

    def test_candidate_validation_boundary(self):
        valid = {
            "selected": "pending",
            "sha256": "a" * 64,
            "file_type": "exe",
        }

        accepted, reason = (
            acquire_samples.candidate_is_valid(
                valid
            )
        )

        self.assertTrue(accepted)
        self.assertEqual(reason, "")

        invalid = dict(valid)
        invalid["file_type"] = "pdf"

        accepted, reason = (
            acquire_samples.candidate_is_valid(
                invalid
            )
        )

        self.assertFalse(accepted)
        self.assertEqual(
            reason,
            "non_pe_artifact",
        )

    def test_candidate_validation_is_not_crypto_rejection(self):
        invalid = {
            "selected": "pending",
            "sha256": "a" * 64,
            "file_type": "pdf",
        }

        accepted, reason = (
            acquire_samples.candidate_is_valid(
                invalid
            )
        )

        self.assertFalse(accepted)
        self.assertEqual(
            reason,
            "non_pe_artifact",
        )

        self.assertNotEqual(
            reason,
            "integrity_failed",
        )

    def test_identity_index_o1_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = (
                Path(tmp)
                / "samples.jsonl"
            )

            sha256 = "a" * 64

            record = {
                "identity": {
                    "sha256": sha256
                }
            }

            manifest.write_text(
                json.dumps(record) + "\n",
                encoding="utf-8",
            )

            index = (
                acquire_samples.CorpusIdentityIndex(
                    manifest
                )
            )

            self.assertTrue(
                index.contains(sha256)
            )

            self.assertFalse(
                index.contains("b" * 64)
            )

    def test_stats_print_supports_slots(self):
        stats = (
            acquire_samples.AcquisitionStats()
        )

        stats.queued = 1

        with patch(
            "builtins.print"
        ) as mocked_print:
            stats.print()

        self.assertTrue(
            mocked_print.called
        )

    def test_reconcile_clean_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            quarantine = (
                root
                / "quarantine"
            )

            manifest = (
                root
                / "samples.jsonl"
            )

            sha256 = "a" * 64

            sample_dir = (
                quarantine
                / sha256
            )

            sample_dir.mkdir(
                parents=True
            )

            (
                sample_dir / "sample"
            ).write_bytes(
                b"sample"
            )

            record = {
                "identity": {
                    "sha256": sha256
                }
            }

            manifest.write_text(
                json.dumps(record) + "\n",
                encoding="utf-8",
            )

            with patch.object(
                acquire_samples,
                "QUARANTINE_ROOT",
                quarantine,
            ), patch.object(
                acquire_samples,
                "SAMPLES_MANIFEST",
                manifest,
            ):
                orphan, missing = (
                    acquire_samples.reconcile_corpus()
                )

            self.assertEqual(
                orphan,
                [],
            )

            self.assertEqual(
                missing,
                [],
            )

    def test_reconcile_detects_orphan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            quarantine = (
                root
                / "quarantine"
            )

            manifest = (
                root
                / "samples.jsonl"
            )

            sha256 = "a" * 64

            sample_dir = (
                quarantine
                / sha256
            )

            sample_dir.mkdir(
                parents=True
            )

            (
                sample_dir / "sample"
            ).write_bytes(
                b"sample"
            )

            with patch.object(
                acquire_samples,
                "QUARANTINE_ROOT",
                quarantine,
            ), patch.object(
                acquire_samples,
                "SAMPLES_MANIFEST",
                manifest,
            ):
                orphan, missing = (
                    acquire_samples.reconcile_corpus()
                )

            self.assertEqual(
                orphan,
                [sha256],
            )

            self.assertEqual(
                missing,
                [],
            )

    def test_recover_orphan_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            quarantine = (
                root
                / "quarantine"
            )

            manifest = (
                root
                / "samples.jsonl"
            )

            candidate = (
                root
                / "candidate_manifest.csv"
            )

            sample = (
                b"synthetic sample"
            )

            sha256 = hashlib.sha256(
                sample
            ).hexdigest()

            sample_dir = (
                quarantine
                / sha256
            )

            sample_dir.mkdir(
                parents=True
            )

            (
                sample_dir / "sample"
            ).write_bytes(sample)

            candidate.write_text(
                (
                    "sha256,sha1,md5,family,"
                    "signature,tags,file_name,"
                    "file_size,file_type,file_format,"
                    "file_arch,first_seen,last_seen,"
                    "reporter,imphash,tlsh,ssdeep,"
                    "source,selected,"
                    "exclusion_reason,dataset_split\n"
                    f"{sha256},,,Emotet,"
                    "Emotet,,sample.exe,"
                    f"{len(sample)},exe,PE32,x86,"
                    ",,,,MalwareBazaar,pending,,\n"
                ),
                encoding="utf-8",
            )

            with patch.object(
                acquire_samples,
                "QUARANTINE_ROOT",
                quarantine,
            ), patch.object(
                acquire_samples,
                "SAMPLES_MANIFEST",
                manifest,
            ), patch.object(
                acquire_samples,
                "CANDIDATE_MANIFEST",
                candidate,
            ), patch.object(
                acquire_samples,
                "ACQUISITION_LOG",
                root / "acquisition.log",
            ), patch(
                "acquire_samples.download_archive"
            ) as downloader:

                recovered, failed = (
                    acquire_samples.recover_orphans()
                )

            self.assertEqual(
                recovered,
                1,
            )

            self.assertEqual(
                failed,
                0,
            )

            downloader.assert_not_called()

            lines = manifest.read_text(
                encoding="utf-8"
            ).splitlines()

            self.assertEqual(
                len(lines),
                1,
            )

            record = json.loads(
                lines[0]
            )

            self.assertEqual(
                record["identity"]["sha256"],
                sha256,
            )

            self.assertEqual(
                record[
                    "acquisition"
                ]["status"],
                "stored",
            )

    def test_recovery_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            quarantine = (
                root
                / "quarantine"
            )

            manifest = (
                root
                / "samples.jsonl"
            )

            candidate = (
                root
                / "candidate_manifest.csv"
            )

            expected = "a" * 64

            sample_dir = (
                quarantine
                / expected
            )

            sample_dir.mkdir(
                parents=True
            )

            (
                sample_dir / "sample"
            ).write_bytes(
                b"wrong content"
            )

            candidate.write_text(
                (
                    "sha256,file_name,file_size,"
                    "file_type,selected\n"
                    f"{expected},sample.exe,13,"
                    "exe,pending\n"
                ),
                encoding="utf-8",
            )

            with patch.object(
                acquire_samples,
                "QUARANTINE_ROOT",
                quarantine,
            ), patch.object(
                acquire_samples,
                "SAMPLES_MANIFEST",
                manifest,
            ), patch.object(
                acquire_samples,
                "CANDIDATE_MANIFEST",
                candidate,
            ), patch.object(
                acquire_samples,
                "ACQUISITION_LOG",
                root / "acquisition.log",
            ):
                recovered, failed = (
                    acquire_samples.recover_orphans()
                )

            self.assertEqual(
                recovered,
                0,
            )

            self.assertEqual(
                failed,
                1,
            )

            self.assertFalse(
                manifest.exists()
            )

    def test_recovery_requires_candidate_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            quarantine = (
                root
                / "quarantine"
            )

            manifest = (
                root
                / "samples.jsonl"
            )

            candidate = (
                root
                / "candidate_manifest.csv"
            )

            sample = b"sample"

            sha256 = hashlib.sha256(
                sample
            ).hexdigest()

            sample_dir = (
                quarantine
                / sha256
            )

            sample_dir.mkdir(
                parents=True
            )

            (
                sample_dir / "sample"
            ).write_bytes(sample)

            candidate.write_text(
                (
                    "sha256,file_name,file_size,"
                    "file_type,selected\n"
                ),
                encoding="utf-8",
            )

            with patch.object(
                acquire_samples,
                "QUARANTINE_ROOT",
                quarantine,
            ), patch.object(
                acquire_samples,
                "SAMPLES_MANIFEST",
                manifest,
            ), patch.object(
                acquire_samples,
                "CANDIDATE_MANIFEST",
                candidate,
            ), patch.object(
                acquire_samples,
                "ACQUISITION_LOG",
                root / "acquisition.log",
            ):
                recovered, failed = (
                    acquire_samples.recover_orphans()
                )

            self.assertEqual(
                recovered,
                0,
            )

            self.assertEqual(
                failed,
                1,
            )

    def test_recovery_does_not_delete_orphan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            quarantine = (
                root
                / "quarantine"
            )

            manifest = (
                root
                / "samples.jsonl"
            )

            candidate = (
                root
                / "candidate_manifest.csv"
            )

            expected = "a" * 64

            sample_dir = (
                quarantine
                / expected
            )

            sample_dir.mkdir(
                parents=True
            )

            sample_path = (
                sample_dir / "sample"
            )

            sample_path.write_bytes(
                b"wrong"
            )

            candidate.write_text(
                (
                    "sha256,file_name,file_size,"
                    "file_type,selected\n"
                    f"{expected},sample.exe,5,"
                    "exe,pending\n"
                ),
                encoding="utf-8",
            )

            with patch.object(
                acquire_samples,
                "QUARANTINE_ROOT",
                quarantine,
            ), patch.object(
                acquire_samples,
                "SAMPLES_MANIFEST",
                manifest,
            ), patch.object(
                acquire_samples,
                "CANDIDATE_MANIFEST",
                candidate,
            ), patch.object(
                acquire_samples,
                "ACQUISITION_LOG",
                root / "acquisition.log",
            ):
                acquire_samples.recover_orphans()

            self.assertTrue(
                sample_path.exists()
            )

    def test_manifest_persistence_state_is_valid(self):
        from corpus_manifest import (
            new_record,
        )

        sha256 = "a" * 64

        record = new_record(
            sha256=sha256,
            sha1=None,
            md5=None,
            provider="MalwareBazaar",
            source_id=sha256,
            query="get_siginfo",
            first_seen=None,
            last_seen=None,
            signature="Emotet",
            tags=[],
            reporter=None,
            original_filename="sample.exe",
            size=1,
            extension=".exe",
            mime_type="application/x-dosexec",
            status=(
                "manifest_persistence_failed"
            ),
            calculated_sha256=sha256,
            cryptographic_verification="passed",
        )

        self.assertEqual(
            record[
                "acquisition"
            ]["status"],
            "manifest_persistence_failed",
        )

    def test_build_record_uses_status_and_timestamp(self):
        row = {
            "sha256": "a" * 64,
            "sha1": "",
            "md5": "",
            "family": "Emotet",
            "signature": "Emotet",
            "tags": "",
            "file_name": "sample.exe",
            "file_size": "10",
            "file_type": "exe",
            "file_format": "PE32",
            "file_arch": "x86",
            "first_seen": "",
            "last_seen": "",
            "reporter": "",
            "imphash": "",
            "tlsh": "",
            "ssdeep": "",
        }

        record = acquire_samples.build_record(
            row,
            "a" * 64,
        )

        acquisition = record[
            "acquisition"
        ]

        self.assertIn(
            "status",
            acquisition,
        )

        self.assertIn(
            "timestamp",
            acquisition,
        )

        self.assertNotIn(
            "state",
            acquisition,
        )

        self.assertNotIn(
            "acquired_at",
            acquisition,
        )


if __name__ == "__main__":
    unittest.main()