#!/usr/bin/env python3
"""
Controlled MalwareBazaar acquisition with crash-recovery safeguards.

Place beside corpus_manifest.py in:
D:\\Honeypot\\Codebase\\tools\\

This module never executes downloaded samples.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import requests

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent
CORPUS_ROOT = PROJECT_ROOT.parent / "Corpus"

CANDIDATE_MANIFEST = (
    PROJECT_ROOT / "Dataset" / "bootstrap" / "MalwareBazaar"
    / "metadata" / "candidate_manifest.csv"
)
SAMPLES_MANIFEST = CORPUS_ROOT / "manifests" / "samples.jsonl"
ACQUISITION_LOG = CORPUS_ROOT / "manifests" / "acquisition.log"
QUARANTINE_ROOT = CORPUS_ROOT / "samples" / "quarantine"
REJECTED_ROOT = CORPUS_ROOT / "samples" / "rejected"
STAGING_ROOT = CORPUS_ROOT / ".staging"

API_URL = "https://mb-api.abuse.ch/api/v1/"
CHUNK_SIZE = 1024 * 1024
SHA256_LEN = 64


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
    """Single manifest scan; O(1) SHA-256 membership thereafter."""

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
                    record = json.loads(line)
                    value = record["identity"]["sha256"].lower()
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

    IMPORTANT: rejection here is a research-scope/metadata decision during
    the validation period, NOT a cryptographic-integrity rejection.
    """
    if row.get("selected") != "pending":
        return False, row.get("exclusion_reason") or "not_selected"

    expected = (row.get("sha256") or "").strip()
    if not valid_sha256(expected):
        return False, "invalid_expected_sha256"

    if row.get("file_type", "").strip().lower() not in {"exe", "dll"}:
        return False, "non_pe_artifact"

    return True, ""


def download_sample(api_key: str, expected_sha256: str, destination: Path) -> None:
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
    """Remove only abandoned staging data; canonical samples are never deleted here."""
    if not STAGING_ROOT.exists():
        return 0
    removed = 0
    for child in STAGING_ROOT.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
        else:
            try:
                child.unlink()
                removed += 1
            except OSError:
                pass
    try:
        STAGING_ROOT.rmdir()
    except OSError:
        pass
    return removed


def verify_final_sample(path: Path, expected: str) -> str:
    calculated = sha256_file(path)
    if calculated.lower() != expected.lower():
        raise RuntimeError(f"final_storage_hash_mismatch:{calculated}")
    return calculated


def acquire(api_key: str, limit: int, dry_run: bool) -> None:
    if not CANDIDATE_MANIFEST.exists():
        raise FileNotFoundError(f"Candidate manifest not found: {CANDIDATE_MANIFEST}")

    # Recovery is O(number of staging entries), not O(number of corpus samples).
    recovered = recover_staging()
    if recovered:
        print(f"Recovered abandoned staging entries: {recovered}")

    identity = CorpusIdentityIndex()
    selected = stored = duplicates = rejected = failed = 0

    # Keep one writer for the entire run. This avoids rescanning/reopening the
    # JSONL manifest for every sample.
    try:
        from corpus_manifest import JsonlManifestWriter
        writer = JsonlManifestWriter(SAMPLES_MANIFEST)
    except ImportError as exc:
        raise RuntimeError(
            "corpus_manifest.py must be available beside acquire_samples.py"
        ) from exc

    with CANDIDATE_MANIFEST.open("r", newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            if limit and selected >= limit:
                break

            valid, reason = candidate_is_valid(row)
            expected = (row.get("sha256") or "").strip().lower()

            if not valid:
                rejected += 1
                if expected:
                    log_event(expected, "candidate_rejected", reason)
                continue

            selected += 1

            if identity.contains(expected):
                duplicates += 1
                log_event(expected, "duplicate", "already_in_corpus")
                continue

            log_event(expected, "queued")
            if dry_run:
                print(f"[DRY-RUN] queued {expected}")
                continue

            STAGING_ROOT.mkdir(parents=True, exist_ok=True)
            stage_dir = Path(tempfile.mkdtemp(prefix=f"{expected[:12]}_", dir=STAGING_ROOT))
            temp_path = stage_dir / "sample"
            final_dir = QUARANTINE_ROOT / expected
            final_path = final_dir / "sample"

            try:
                log_event(expected, "download_started")
                download_sample(api_key, expected, temp_path)

                if not temp_path.exists() or temp_path.stat().st_size == 0:
                    raise RuntimeError("empty_download")
                log_event(expected, "download_completed")

                log_event(expected, "cryptographic_verification")
                calculated = sha256_file(temp_path)
                if calculated.lower() != expected:
                    log_event(
                        expected, "integrity_failed",
                        f"calculated_sha256={calculated}",
                    )
                    rejected += 1
                    continue
                log_event(expected, "cryptographically_verified")

                # Re-check immediately before commit to close the normal
                # check-then-create race without introducing locks/coordination.
                if identity.contains(expected) or final_dir.exists():
                    duplicates += 1
                    log_event(expected, "duplicate", "appeared_during_acquisition")
                    continue

                log_event(expected, "storage_started")
                QUARANTINE_ROOT.mkdir(parents=True, exist_ok=True)

                # The staging directory is on the same filesystem as Corpus,
                # so os.replace gives an atomic directory rename on Windows.
                os.replace(stage_dir, final_dir)

                # Verify the exact file now present at its canonical path.
                verify_final_sample(final_path, expected)

                record = build_record(row, expected)
                writer.append(record)
                identity.add(expected)

                log_event(expected, "stored")
                log_event(expected, "ready_for_analysis")
                stored += 1

            except Exception as exc:
                failed += 1
                # If final storage exists but the manifest append failed, leave
                # the canonical bytes intact for recovery/audit; never silently
                # delete a verified sample. The next run can detect the orphan.
                log_event(expected, "acquisition_failed", type(exc).__name__)
                print(f"[FAILED] {expected}: {exc}", file=sys.stderr)
            finally:
                if stage_dir.exists():
                    shutil.rmtree(stage_dir, ignore_errors=True)

    print(
        f"Selected={selected} Stored={stored} Duplicates={duplicates} "
        f"Rejected={rejected} Failed={failed}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Acquire and cryptographically verify MalwareBazaar candidates."
    )
    parser.add_argument("--limit", type=int, default=0,
                        help="Maximum eligible candidates; 0 means all.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate/queue only; never download.")
    args = parser.parse_args()

    try:
        acquire(load_api_key(), args.limit, args.dry_run)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
