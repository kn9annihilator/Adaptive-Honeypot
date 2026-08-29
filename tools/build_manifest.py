import csv
import os
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv

#query = "get_file"
#For the time being, I'm commenting out this line as we're not focussing on downloading the samples in this phase.
API_URL = "https://mb-api.abuse.ch/api/v1/"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "bootstrap"
    / "MalwareBazaar"
    / "metadata"
    / "candidate_manifest.csv"
)

FAMILY = "Emotet"
LIMIT = 50


def load_api_key() -> str:
    """Load the MalwareBazaar Auth-Key from .env."""
    load_dotenv(PROJECT_ROOT / ".env")

    api_key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

    if not api_key:
        print("ERROR: MALWAREBAZAAR_AUTH_KEY is not set.")
        print(f"Expected .env at: {PROJECT_ROOT / '.env'}")
        sys.exit(1)

    return api_key


def query_malwarebazaar(api_key: str, family: str, limit: int) -> list[dict]:
    """Query MalwareBazaar metadata only."""
    headers = {
        "Auth-Key": api_key,
    }

    data = {
        "query": "get_siginfo",
        "signature": family,
        "limit": limit,
    }

    response = requests.post(
        API_URL,
        headers=headers,
        data=data,
        timeout=30,
    )

    response.raise_for_status()

    result = response.json()

    if result.get("query_status") != "ok":
        print("ERROR: MalwareBazaar returned an unsuccessful query status.")
        print(result.get("query_status"))
        sys.exit(1)

    return result.get("data", [])


def is_pe_candidate(sample: dict) -> bool:
    """Keep PE executables and DLLs for the initial corpus."""
    file_type = (sample.get("file_type") or "").lower()
    mime = (sample.get("file_type_mime") or "").lower()

    return (
        file_type in {"exe", "dll"}
        or mime == "application/x-dosexec"
    )


def build_rows(samples: list[dict], family: str) -> list[dict]:
    """Convert MalwareBazaar records into our manifest schema."""
    rows = []
    seen_sha256 = set()

    for sample in samples:
        sha256 = sample.get("sha256_hash")

        if not sha256:
            continue

        # SHA-256 is our primary deduplication key.
        if sha256 in seen_sha256:
            continue

        seen_sha256.add(sha256)

        selected = "pending"
        exclusion_reason = ""

        if not is_pe_candidate(sample):
            selected = "no"
            exclusion_reason = "non_pe_artifact"

        rows.append(
            {
                "sha256": sha256,
                "sha1": sample.get("sha1_hash"),
                "md5": sample.get("md5_hash"),
                "family": family,
                "signature": sample.get("signature"),
                "tags": ",".join(sample.get("tags") or []),
                "file_name": sample.get("file_name"),
                "file_size": sample.get("file_size"),
                "file_type": sample.get("file_type"),
                "file_format": sample.get("file_format"),
                "file_arch": sample.get("file_arch"),
                "first_seen": sample.get("first_seen"),
                "last_seen": sample.get("last_seen"),
                "reporter": sample.get("reporter"),
                "imphash": sample.get("imphash"),
                "tlsh": sample.get("tlsh"),
                "ssdeep": sample.get("ssdeep"),
                "source": "MalwareBazaar",
                "selected": selected,
                "exclusion_reason": exclusion_reason,
                "dataset_split": "",
            }
        )

    return rows


def write_manifest(rows: list[dict]) -> None:
    """Write the candidate manifest CSV."""
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "sha256",
        "sha1",
        "md5",
        "family",
        "signature",
        "tags",
        "file_name",
        "file_size",
        "file_type",
        "file_format",
        "file_arch",
        "first_seen",
        "last_seen",
        "reporter",
        "imphash",
        "tlsh",
        "ssdeep",
        "source",
        "selected",
        "exclusion_reason",
        "dataset_split",
    ]

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    api_key = load_api_key()

    print(f"Querying MalwareBazaar metadata for: {FAMILY}")
    print(f"Candidate limit: {LIMIT}")
    print("Download operation: DISABLED")

    samples = query_malwarebazaar(
        api_key=api_key,
        family=FAMILY,
        limit=LIMIT,
    )

    rows = build_rows(samples, FAMILY)
    write_manifest(rows)

    pe_count = sum(row["selected"] == "pending" for row in rows)
    excluded_count = sum(row["selected"] == "no" for row in rows)

    print()
    print("Manifest generation complete.")
    print(f"Records received: {len(samples)}")
    print(f"PE candidates:     {pe_count}")
    print(f"Excluded:          {excluded_count}")
    print(f"Manifest:          {OUTPUT_FILE}")


if __name__ == "__main__":
    main()