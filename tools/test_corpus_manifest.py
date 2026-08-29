import json
import tempfile
import unittest
from pathlib import Path

from corpus_manifest import (
    DuplicateSampleError,
    JsonlManifestWriter,
    ManifestValidationError,
    CorpusIdentityIndex,
    new_record,
    sha256_file,
    validate_record,
)

SHA256 = "a" * 64
SHA1 = "b" * 40
MD5 = "c" * 32


def make_record(**overrides):
    data = dict(
        sha256=SHA256,
        sha1=SHA1,
        md5=MD5,
        provider="MalwareBazaar",
        source_id="source-1",
        query="Emotet",
        first_seen="2026-01-01T00:00:00Z",
        last_seen=None,
        signature="Emotet",
        tags=["Emotet", "exe"],
        reporter="researcher",
        original_filename="sample.exe",
        size=1234,
        extension=".exe",
        mime_type="application/x-dosexec",
        file_type="exe",
        file_format="PE",
        architecture="AMD64",
        imphash=None,
        tlsh=None,
        ssdeep=None,
        status="stored",
        calculated_sha256=SHA256,
        cryptographic_verification="passed",
        storage_path=f"Corpus/samples/quarantine/{SHA256}/sample",
    )
    data.update(overrides)
    return new_record(**data)


class ManifestTests(unittest.TestCase):
    def test_valid_record(self):
        self.assertEqual(validate_record(make_record())["identity"]["sample_id"], SHA256)

    def test_sample_id_must_match_sha256(self):
        record = make_record()
        record["identity"]["sample_id"] = "d" * 64
        with self.assertRaises(ManifestValidationError):
            validate_record(record)

    def test_expected_hash_must_match_identity(self):
        record = make_record()
        record["acquisition"]["expected_sha256"] = "d" * 64
        with self.assertRaises(ManifestValidationError):
            validate_record(record)

    def test_calculated_hash_must_match_identity_when_passed(self):
        record = make_record()
        record["acquisition"]["calculated_sha256"] = "d" * 64
        with self.assertRaises(ManifestValidationError):
            validate_record(record)

    def test_state_model(self):
        record = make_record(status="cryptographic_verification", cryptographic_verification="in_progress", calculated_sha256=None)
        self.assertEqual(validate_record(record)["acquisition"]["status"], "cryptographic_verification")

    def test_integrity_failure_requires_mismatch(self):
        record = make_record(status="integrity_failed", cryptographic_verification="failed", calculated_sha256="d" * 64)
        self.assertEqual(validate_record(record)["acquisition"]["status"], "integrity_failed")

    def test_stored_requires_crypto_pass(self):
        record = make_record()
        record["acquisition"]["cryptographic_verification"] = "not_performed"
        with self.assertRaises(ManifestValidationError):
            validate_record(record)

    def test_writer_creates_valid_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "samples.jsonl"
            writer = JsonlManifestWriter(path)
            writer.append(make_record())
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["identity"]["sha256"], SHA256)

    def test_writer_rejects_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "samples.jsonl"
            writer = JsonlManifestWriter(path)
            record = make_record()
            writer.append(record)
            with self.assertRaises(DuplicateSampleError):
                writer.append(record)

    def test_identity_index_loads_once_and_detects_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "samples.jsonl"
            writer = JsonlManifestWriter(path)
            writer.append(make_record())
            index = CorpusIdentityIndex.load(path)
            self.assertTrue(index.contains(SHA256))
            self.assertEqual(len(index.sha256s), 1)

    def test_sha256_file_streaming(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(b"honeypot-corpus-test" * 10000)
            import hashlib
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(sha256_file(path), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
