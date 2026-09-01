#!/usr/bin/env python3
"""Controlled MalwareBazaar acquisition with AES-ZIP extraction and recovery checks."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path

import requests

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent
CORPUS_ROOT = PROJECT_ROOT.parent / "Corpus"

CANDIDATE_MANIFEST = PROJECT_ROOT / "Dataset" / "bootstrap" / "MalwareBazaar" / "metadata" / "candidate_manifest.csv"
SAMPLES_MANIFEST = CORPUS_ROOT / "manifests" / "samples.jsonl"
ACQUISITION_LOG = CORPUS_ROOT / "manifests" / "acquisition.log"
QUARANTINE_ROOT = CORPUS_ROOT / "samples" / "quarantine"
STAGING_ROOT = CORPUS_ROOT / ".staging"

API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"
CHUNK_SIZE = 1024 * 1024
SHA256_LEN = 64


@dataclass(slots=True)
class AcquisitionStats:
    candidates_considered: int = 0
    candidates_eligible: int = 0
    queued: int = 0
    downloads_completed: int = 0
    cryptographically_verified: int = 0
    stored: int = 0
    duplicates: int = 0
    candidate_validation_rejected: int = 0
    archive_validation_failed: int = 0
    integrity_failed: int = 0
    download_failed: int = 0
    storage_failed: int = 0

    def print(self) -> None:
        for field in fields(self):
            name = field.name
            value = getattr(self, name)
            print(f"{name.replace('_', ' ').title()}: {value}")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log_event(sha256: str, state: str, detail: str = "") -> None:
    ACQUISITION_LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"{utc_now()} | {state} | sha256={sha256}"
    if detail:
        line += f" | {detail}"
    with ACQUISITION_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def valid_sha256(value: str | None) -> bool:
    return bool(value) and len(value) == SHA256_LEN and all(
        c in "0123456789abcdefABCDEF" for c in value
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CorpusIdentityIndex:
    """One manifest scan; O(1) membership after initialization."""

    __slots__ = ("_sha256",)

    def __init__(self, manifest_path: Path = SAMPLES_MANIFEST):
        self._sha256: set[str] = set()
        if not manifest_path.exists():
            return
        with manifest_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)["identity"]["sha256"].lower()
                    if valid_sha256(value):
                        self._sha256.add(value)
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue

    def contains(self, sha256: str) -> bool:
        return sha256.lower() in self._sha256

    def add(self, sha256: str) -> None:
        self._sha256.add(sha256.lower())


def load_api_key() -> str:
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")
    key = os.getenv("MALWAREBAZAAR_AUTH_KEY")
    if not key:
        raise RuntimeError(
            f"MALWAREBAZAAR_AUTH_KEY is not set; expected {PROJECT_ROOT / '.env'}"
        )
    return key


def candidate_is_valid(row: dict[str, str]) -> tuple[bool, str]:
    """
    Candidate-stage validation.

    IMPORTANT: rejection here is a scope/metadata decision during the
    validation period, NOT a cryptographic-integrity rejection.
    """
    if row.get("selected") != "pending":
        return False, row.get("exclusion_reason") or "not_selected"

    expected = (row.get("sha256") or "").strip()
    if not valid_sha256(expected):
        return False, "invalid_expected_sha256"

    if row.get("file_type", "").strip().lower() not in {"exe", "dll"}:
        return False, "non_pe_artifact"

    return True, ""


def download_archive(api_key: str, expected_sha256: str, destination: Path) -> None:
    response = requests.post(
        API_URL,
        headers={"Auth-Key": api_key},
        data={"query": "get_file", "sha256_hash": expected_sha256},
        stream=True,
        timeout=(15, 120),
    )
    response.raise_for_status()

    with destination.open("wb") as fh:
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            if chunk:
                fh.write(chunk)


def extract_sample(archive_path: Path, output_path: Path) -> str:
    """Extract exactly one regular AES-ZIP member to a fixed safe path.

    Member paths are never used as filesystem paths, preventing ZIP path
    traversal. Extraction is streamed to avoid loading the sample into RAM.
    """
    try:
        import pyzipper
    except ImportError as exc:
        raise RuntimeError(
            "pyzipper is required for MalwareBazaar AES-128 ZIP extraction. "
            "Install with: python -m pip install pyzipper"
        ) from exc

    with pyzipper.AESZipFile(archive_path, "r") as zf:
        members = [info for info in zf.infolist() if not info.is_dir()]
        if len(members) != 1:
            raise ValueError(f"expected_one_file_in_archive:{len(members)}")

        info = members[0]
        zf.setpassword(ZIP_PASSWORD)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info, "r") as src, output_path.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=CHUNK_SIZE)

        if not output_path.exists() or output_path.stat().st_size == 0:
            raise ValueError("empty_extracted_sample")

        return info.filename


def verify_hash(path: Path, expected_sha256: str) -> str:
    calculated = sha256_file(path)
    if calculated.lower() != expected_sha256.lower():
        raise ValueError(f"sha256_mismatch:{calculated}")
    return calculated


def build_record(row: dict[str, str], calculated_sha256: str) -> dict:
    expected = row["sha256"].strip().lower()
    return {
        "schema_version": 1,
        "identity": {
            "sample_id": expected,
            "sha256": expected,
            "sha1": (row.get("sha1") or "").strip().lower() or None,
            "md5": (row.get("md5") or "").strip().lower() or None,
        },
        "source": {
            "provider": "MalwareBazaar",
            "source_id": expected,
            "family": row.get("family") or None,
            "signature": row.get("signature") or None,
            "tags": [x for x in (row.get("tags") or "").split(",") if x],
            "first_seen": row.get("first_seen") or None,
            "last_seen": row.get("last_seen") or None,
            "reporter": row.get("reporter") or None,
        },
        "file": {
            "original_filename": row.get("file_name") or None,
            "size": int(row["file_size"]) if row.get("file_size", "").isdigit() else None,
            "extension": Path(row.get("file_name") or "").suffix.lower() or None,
            "mime_type": None,
            "file_type": row.get("file_type") or None,
            "file_format": row.get("file_format") or None,
            "architecture": row.get("file_arch") or None,
        },
        "acquisition": {
            "state": "stored",
            "expected_sha256": expected,
            "calculated_sha256": calculated_sha256.lower(),
            "cryptographic_verification": "passed",
            "acquired_at": utc_now(),
            "storage_path": str(QUARANTINE_ROOT / expected / "sample"),
        },
        "processing": {
            "analysis_status": "pending",
            "graph_status": "pending",
        },
    }


def recover_staging() -> int:
    """Delete only abandoned staging transactions; never touch canonical samples."""
    if not STAGING_ROOT.exists():
        return 0
    removed = 0
    for child in list(STAGING_ROOT.iterdir()):
        try:
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
            removed += 1
        except OSError:
            pass
    try:
        STAGING_ROOT.rmdir()
    except OSError:
        pass
    return removed


def reconcile_corpus() -> tuple[list[str], list[str]]:
    """Return (orphan_sample_hashes, manifest_records_missing_files)."""
    manifest_hashes: set[str] = set()
    if SAMPLES_MANIFEST.exists():
        with SAMPLES_MANIFEST.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    value = rec["identity"]["sha256"].lower()
                    if valid_sha256(value):
                        manifest_hashes.add(value)
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue

    canonical: set[str] = set()
    if QUARANTINE_ROOT.exists():
        for d in QUARANTINE_ROOT.iterdir():
            if d.is_dir() and valid_sha256(d.name) and (d / "sample").is_file():
                canonical.add(d.name.lower())

    return sorted(canonical - manifest_hashes), sorted(manifest_hashes - canonical)


def acquire(api_key: str, limit: int, dry_run: bool) -> AcquisitionStats:
    if not CANDIDATE_MANIFEST.exists():
        raise FileNotFoundError(f"Candidate manifest not found: {CANDIDATE_MANIFEST}")

    recovered = recover_staging()
    if recovered:
        print(f"Recovered abandoned staging entries: {recovered}")

    identity = CorpusIdentityIndex()
    stats = AcquisitionStats()

    from corpus_manifest import JsonlManifestWriter
    writer = JsonlManifestWriter(SAMPLES_MANIFEST)

    with CANDIDATE_MANIFEST.open("r", newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            stats.candidates_considered += 1
            if limit and stats.candidates_eligible >= limit:
                break

            valid, reason = candidate_is_valid(row)
            expected = (row.get("sha256") or "").strip().lower()

            if not valid:
                stats.candidate_validation_rejected += 1
                if expected:
                    log_event(expected, "candidate_rejected", reason)
                continue

            stats.candidates_eligible += 1

            if identity.contains(expected) or (QUARANTINE_ROOT / expected / "sample").is_file():
                stats.duplicates += 1
                log_event(expected, "duplicate", "already_in_corpus")
                continue

            stats.queued += 1
            log_event(expected, "queued")

            if dry_run:
                print(f"[DRY-RUN] queued {expected}")
                continue

            STAGING_ROOT.mkdir(parents=True, exist_ok=True)
            stage_dir = Path(tempfile.mkdtemp(prefix=f"{expected[:12]}_", dir=STAGING_ROOT))
            archive_path = stage_dir / "archive.zip"
            sample_path = stage_dir / "sample"
            final_dir = QUARANTINE_ROOT / expected
            final_path = final_dir / "sample"

            try:
                log_event(expected, "download_started")
                try:
                    download_archive(api_key, expected, archive_path)
                    if not archive_path.is_file() or archive_path.stat().st_size == 0:
                        raise ValueError("empty_download")
                    stats.downloads_completed += 1
                    log_event(expected, "download_completed")
                except Exception as exc:
                    stats.download_failed += 1
                    log_event(expected, "download_failed", type(exc).__name__)
                    print(f"[DOWNLOAD FAILED] {expected}: {exc}", file=sys.stderr)
                    continue

                try:
                    log_event(expected, "archive_validation")
                    extract_name = extract_sample(archive_path, sample_path)
                    log_event(expected, "archive_extracted", extract_name)
                except Exception as exc:
                    stats.archive_validation_failed += 1
                    log_event(expected, "archive_validation_failed", type(exc).__name__)
                    print(f"[ARCHIVE FAILED] {expected}: {exc}", file=sys.stderr)
                    continue

                try:
                    log_event(expected, "cryptographic_verification")
                    calculated = verify_hash(sample_path, expected)
                    stats.cryptographically_verified += 1
                    log_event(expected, "cryptographically_verified")
                except Exception as exc:
                    stats.integrity_failed += 1
                    log_event(expected, "integrity_failed", str(exc))
                    print(f"[INTEGRITY FAILED] {expected}: {exc}", file=sys.stderr)
                    continue

                if identity.contains(expected) or final_dir.exists():
                    stats.duplicates += 1
                    log_event(expected, "duplicate", "appeared_during_acquisition")
                    continue

                try:
                    log_event(expected, "storage_started")
                    QUARANTINE_ROOT.mkdir(parents=True, exist_ok=True)
                    os.replace(stage_dir, final_dir)

                    final_calculated = verify_hash(final_path, expected)
                    if final_calculated.lower() != calculated.lower():
                        raise ValueError("post_commit_hash_changed")

                    record = build_record(row, final_calculated)
                    writer.append(record)
                    identity.add(expected)

                    stats.stored += 1
                    log_event(expected, "stored")
                    log_event(expected, "ready_for_analysis")
                except Exception as exc:
                    stats.storage_failed += 1
                    log_event(expected, "storage_failed", type(exc).__name__)
                    print(f"[STORAGE FAILED] {expected}: {exc}", file=sys.stderr)
                    # Never delete a canonical sample merely because JSONL
                    # persistence failed; reconciliation will surface it.
                    continue
            finally:
                if stage_dir.exists():
                    shutil.rmtree(stage_dir, ignore_errors=True)

    stats.print()
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Acquire MalwareBazaar samples with AES-ZIP extraction and SHA-256 verification."
    )
    parser.add_argument("--limit", type=int, default=0,
                        help="Maximum eligible candidates to process; 0 means all.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate/queue only; never download.")
    parser.add_argument("--reconcile", action="store_true",
                        help="Check canonical quarantine against samples.jsonl; no mutation.")
    args = parser.parse_args()

    try:
        if args.reconcile:
            orphan, missing = reconcile_corpus()
            print(f"Orphan canonical samples: {len(orphan)}")
            print(f"Manifest records missing files: {len(missing)}")
            for value in orphan:
                print(f"ORPHAN_SAMPLE {value}")
            for value in missing:
                print(f"MISSING_FILE {value}")
            raise SystemExit(1 if orphan or missing else 0)

        acquire(load_api_key(), args.limit, args.dry_run)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
