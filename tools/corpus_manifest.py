"""Corpus manifest schema, validator, identity index, and JSONL writer."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
MD5_RE = re.compile(r"^[0-9a-f]{32}$")


ACQUISITION_STATES = frozenset(
    {
        "candidate",
        "queued",
        "download_started",
        "download_completed",
        "cryptographic_verification",
        "cryptographically_verified",
        "storage_started",
        "stored",
        "ready_for_analysis",
        "download_failed",
        "integrity_failed",
        "storage_failed",
        "manifest_persistence_failed",
        "duplicate",
    }
)

PROCESSING_STATES = frozenset(
    {"pending", "running", "complete", "failed", "skipped"}
)

CRYPTO_STATES = frozenset(
    {"not_performed", "in_progress", "passed", "failed"}
)


REQUIRED_TOP = frozenset(
    {
        "schema_version",
        "identity",
        "source",
        "file",
        "acquisition",
        "processing",
    }
)

REQUIRED_IDENTITY = frozenset(
    {
        "sample_id",
        "sha256",
    }
)

REQUIRED_SOURCE = frozenset(
    {
        "provider",
    }
)

REQUIRED_FILE = frozenset(
    {
        "size",
        "extension",
        "mime_type",
    }
)

REQUIRED_ACQUISITION = frozenset(
    {
        "status",
        "timestamp",
        "expected_sha256",
        "calculated_sha256",
        "cryptographic_verification",
    }
)

REQUIRED_PROCESSING = frozenset(
    {
        "analysis_status",
        "graph_status",
    }
)


class ManifestError(ValueError):
    """Base manifest error."""


class ManifestValidationError(ManifestError):
    """Raised when a manifest record violates the schema."""


class DuplicateSampleError(ManifestError):
    """Raised when a sample already exists in the manifest."""


def utc_now() -> str:
    """Return the current UTC time as RFC-3339 with Z suffix."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestValidationError(f"{name} must be an object")
    return value


def _required(
    obj: Mapping[str, Any],
    keys: frozenset[str],
    name: str,
) -> None:
    missing = keys - obj.keys()

    if missing:
        raise ManifestValidationError(
            f"{name} missing required field(s): "
            f"{', '.join(sorted(missing))}"
        )


def _hash(
    value: Any,
    pattern: re.Pattern[str],
    name: str,
) -> str:
    if not isinstance(value, str):
        raise ManifestValidationError(f"{name} must be a string")

    value = value.lower()

    if not pattern.fullmatch(value):
        raise ManifestValidationError(
            f"{name} has invalid format"
        )

    return value


def _optional_string(
    obj: Mapping[str, Any],
    key: str,
    section: str,
) -> None:
    if (
        key in obj
        and obj[key] is not None
        and not isinstance(obj[key], str)
    ):
        raise ManifestValidationError(
            f"{section}.{key} must be a string or null"
        )


def _timestamp(value: Any, name: str) -> None:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ManifestValidationError(
            f"{name} must be a UTC RFC 3339 timestamp ending in Z"
        )

    try:
        datetime.fromisoformat(
            value[:-1] + "+00:00"
        )
    except ValueError as exc:
        raise ManifestValidationError(
            f"{name} is not a valid RFC 3339 timestamp"
        ) from exc


def validate_record(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Validate and normalize one manifest record.

    The caller's object is never intentionally mutated.
    """
    record = _mapping(record, "record")

    _required(record, REQUIRED_TOP, "record")

    if record["schema_version"] != SCHEMA_VERSION:
        raise ManifestValidationError(
            f"unsupported schema_version="
            f"{record['schema_version']!r}"
        )

    identity = _mapping(
        record["identity"],
        "identity",
    )
    source = _mapping(
        record["source"],
        "source",
    )
    file_info = _mapping(
        record["file"],
        "file",
    )
    acquisition = _mapping(
        record["acquisition"],
        "acquisition",
    )
    processing = _mapping(
        record["processing"],
        "processing",
    )

    _required(
        identity,
        REQUIRED_IDENTITY,
        "identity",
    )
    _required(
        source,
        REQUIRED_SOURCE,
        "source",
    )
    _required(
        file_info,
        REQUIRED_FILE,
        "file",
    )
    _required(
        acquisition,
        REQUIRED_ACQUISITION,
        "acquisition",
    )
    _required(
        processing,
        REQUIRED_PROCESSING,
        "processing",
    )

    sha256 = _hash(
        identity["sha256"],
        SHA256_RE,
        "identity.sha256",
    )

    sample_id = _hash(
        identity["sample_id"],
        SHA256_RE,
        "identity.sample_id",
    )

    if sample_id != sha256:
        raise ManifestValidationError(
            "identity.sample_id must equal identity.sha256"
        )

    for key, pattern in (
        ("sha1", SHA1_RE),
        ("md5", MD5_RE),
    ):
        if identity.get(key) is not None:
            _hash(
                identity[key],
                pattern,
                f"identity.{key}",
            )

    if (
        not isinstance(source["provider"], str)
        or not source["provider"].strip()
    ):
        raise ManifestValidationError(
            "source.provider must be a non-empty string"
        )

    for key in (
        "source_id",
        "query",
        "first_seen",
        "last_seen",
        "signature",
        "reporter",
    ):
        _optional_string(
            source,
            key,
            "source",
        )

    if "tags" in source:
        if (
            not isinstance(source["tags"], list)
            or any(
                not isinstance(item, str)
                for item in source["tags"]
            )
        ):
            raise ManifestValidationError(
                "source.tags must be a list of strings"
            )

    size = file_info["size"]

    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 1
    ):
        raise ManifestValidationError(
            "file.size must be a positive integer"
        )

    for key in (
        "original_filename",
        "extension",
        "mime_type",
        "file_type",
        "file_format",
        "architecture",
        "imphash",
        "tlsh",
        "ssdeep",
    ):
        _optional_string(
            file_info,
            key,
            "file",
        )

    status = acquisition["status"]

    if status not in ACQUISITION_STATES:
        raise ManifestValidationError(
            "acquisition.status must be one of "
            f"{sorted(ACQUISITION_STATES)}"
        )

    _timestamp(
        acquisition["timestamp"],
        "acquisition.timestamp",
    )

    expected = _hash(
        acquisition["expected_sha256"],
        SHA256_RE,
        "acquisition.expected_sha256",
    )

    if expected != sha256:
        raise ManifestValidationError(
            "acquisition.expected_sha256 must equal "
            "identity.sha256"
        )

    calculated_value = acquisition["calculated_sha256"]

    calculated = (
        None
        if calculated_value is None
        else _hash(
            calculated_value,
            SHA256_RE,
            "acquisition.calculated_sha256",
        )
    )

    crypto = acquisition["cryptographic_verification"]

    if crypto not in CRYPTO_STATES:
        raise ManifestValidationError(
            "acquisition.cryptographic_verification must be one of "
            f"{sorted(CRYPTO_STATES)}"
        )

    if crypto == "passed":
        if calculated != sha256:
            raise ManifestValidationError(
                "passed cryptographic verification requires "
                "calculated_sha256 == identity.sha256"
            )

    elif crypto == "failed":
        if calculated is None or calculated == sha256:
            raise ManifestValidationError(
                "failed cryptographic verification requires "
                "a calculated hash different from identity.sha256"
            )

    elif crypto == "in_progress":
        if calculated is not None:
            raise ManifestValidationError(
                "in-progress cryptographic verification cannot "
                "have calculated_sha256"
            )

    if (
        status == "cryptographic_verification"
        and crypto != "in_progress"
    ):
        raise ManifestValidationError(
            "cryptographic_verification status requires "
            "verification state in_progress"
        )

    if status in {
        "cryptographically_verified",
        "storage_started",
        "stored",
        "ready_for_analysis",
        "manifest_persistence_failed",
    }:
        if crypto != "passed":
            raise ManifestValidationError(
                f"{status} requires "
                "cryptographic_verification=passed"
            )

    if status == "integrity_failed":
        if crypto != "failed":
            raise ManifestValidationError(
                "integrity_failed requires "
                "cryptographic_verification=failed"
            )

    for key in (
        "download_url",
        "storage_path",
        "error",
    ):
        _optional_string(
            acquisition,
            key,
            "acquisition",
        )

    for key in (
        "analysis_status",
        "graph_status",
    ):
        if processing[key] not in PROCESSING_STATES:
            raise ManifestValidationError(
                f"processing.{key} must be one of "
                f"{sorted(PROCESSING_STATES)}"
            )

    normalized = json.loads(
        json.dumps(
            record,
            ensure_ascii=False,
        )
    )

    normalized["identity"]["sample_id"] = sha256
    normalized["identity"]["sha256"] = sha256

    normalized["acquisition"][
        "expected_sha256"
    ] = expected

    normalized["acquisition"][
        "calculated_sha256"
    ] = calculated

    return normalized


def new_record(
    *,
    sha256: str,
    sha1: str | None,
    md5: str | None,
    provider: str,
    source_id: str | None,
    query: str | None,
    first_seen: str | None,
    last_seen: str | None,
    signature: str | None,
    tags: Iterable[str] | None,
    reporter: str | None,
    original_filename: str | None,
    size: int,
    extension: str,
    mime_type: str,
    file_type: str | None = None,
    file_format: str | None = None,
    architecture: str | None = None,
    imphash: str | None = None,
    tlsh: str | None = None,
    ssdeep: str | None = None,
    status: str = "stored",
    calculated_sha256: str | None = None,
    cryptographic_verification: str = "passed",
    acquisition_timestamp: str | None = None,
    download_url: str | None = None,
    storage_path: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    sha256 = _hash(
        sha256,
        SHA256_RE,
        "sha256",
    )

    if (
        calculated_sha256 is None
        and cryptographic_verification == "passed"
    ):
        calculated_sha256 = sha256

    record = {
        "schema_version": SCHEMA_VERSION,
        "identity": {
            "sample_id": sha256,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
        },
        "source": {
            "provider": provider,
            "source_id": source_id,
            "query": query,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "signature": signature,
            "tags": list(tags or []),
            "reporter": reporter,
        },
        "file": {
            "original_filename": original_filename,
            "size": size,
            "extension": extension,
            "mime_type": mime_type,
            "file_type": file_type,
            "file_format": file_format,
            "architecture": architecture,
            "imphash": imphash,
            "tlsh": tlsh,
            "ssdeep": ssdeep,
        },
        "acquisition": {
            "status": status,
            "timestamp": acquisition_timestamp or utc_now(),
            "expected_sha256": sha256,
            "calculated_sha256": calculated_sha256,
            "cryptographic_verification":
                cryptographic_verification,
            "download_url": download_url,
            "storage_path": storage_path,
            "error": error,
        },
        "processing": {
            "analysis_status": "pending",
            "graph_status": "pending",
        },
    }

    return validate_record(record)


@dataclass(slots=True)
class CorpusIdentityIndex:
    """One-pass manifest index; membership checks are O(1)."""

    manifest_path: Path
    sha256s: set[str]

    @classmethod
    def load(
        cls,
        manifest_path: Path,
    ) -> "CorpusIdentityIndex":
        path = Path(manifest_path)
        hashes: set[str] = set()

        if not path.exists():
            return cls(path, hashes)

        with path.open(
            "r",
            encoding="utf-8",
            errors="strict",
        ) as handle:
            for line_number, line in enumerate(
                handle,
                1,
            ):
                if not line.strip():
                    continue

                try:
                    normalized = validate_record(
                        json.loads(line)
                    )
                except (
                    json.JSONDecodeError,
                    ManifestValidationError,
                ) as exc:
                    raise ManifestValidationError(
                        "invalid manifest record at "
                        f"line {line_number}: {exc}"
                    ) from exc

                sha256 = normalized[
                    "identity"
                ]["sha256"]

                if sha256 in hashes:
                    raise ManifestValidationError(
                        "duplicate SHA-256 at line "
                        f"{line_number}: {sha256}"
                    )

                hashes.add(sha256)

        return cls(path, hashes)

    def contains(self, sha256: str) -> bool:
        return (
            _hash(
                sha256,
                SHA256_RE,
                "sha256",
            )
            in self.sha256s
        )

    def add(self, sha256: str) -> None:
        self.sha256s.add(
            _hash(
                sha256,
                SHA256_RE,
                "sha256",
            )
        )

    def refresh(self) -> None:
        self.sha256s = self.load(
            self.manifest_path
        ).sha256s


class JsonlManifestWriter:
    """
    Append-only JSONL writer with validation and
    O(1) duplicate detection.
    """

    def __init__(
        self,
        manifest_path: Path,
    ):
        self.manifest_path = Path(manifest_path)

        self.manifest_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.identity_index = (
            CorpusIdentityIndex.load(
                self.manifest_path
            )
        )

    def append(
        self,
        record: Mapping[str, Any],
    ) -> None:
        normalized = validate_record(record)

        sha256 = normalized[
            "identity"
        ]["sha256"]

        if self.identity_index.contains(sha256):
            raise DuplicateSampleError(
                f"sample already exists: {sha256}"
            )

        payload = (
            json.dumps(
                normalized,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )

        with self.manifest_path.open(
            "a",
            encoding="utf-8",
            newline="",
        ) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        self.identity_index.add(sha256)


def sha256_file(
    path: Path,
    chunk_size: int = 1024 * 1024,
) -> str:
    """Calculate SHA-256 using bounded memory."""

    if chunk_size <= 0:
        raise ValueError(
            "chunk_size must be positive"
        )

    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(chunk_size),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()