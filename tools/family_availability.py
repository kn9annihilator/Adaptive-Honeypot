
import csv
import os
import sys
from pathlib import Path
from collections import Counter
from datetime import datetime

import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "bootstrap"
    / "MalwareBazaar"
    / "metadata"
    / "family_availability.csv"
)

API_URL = "https://mb-api.abuse.ch/api/v1/"

FAMILIES = [
    "Emotet",
    "TrickBot",
    "QakBot",
    "IcedID",
    "Dridex",
    "AgentTesla",
    "FormBook",
    "LokiBot",
    "Remcos",
    "AsyncRAT",
    "njRAT",
    "RedLine",
    "Raccoon",
    "SmokeLoader",
    "GootLoader",
    "AveMaria",
    "BitRAT",
    "XWorm",
    "NanoCore",
    "DarkComet",
]

QUERY_LIMIT = 1000


def load_api_key() -> str:
    load_dotenv(PROJECT_ROOT / ".env")

    api_key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

    if not api_key:
        print("ERROR: MALWAREBAZAAR_AUTH_KEY is not set in .env")
        print(f"Expected .env at: {PROJECT_ROOT / '.env'}")
        sys.exit(1)

    return api_key


def query_family(api_key: str, family: str) -> list[dict]:
    headers = {
        "Auth-Key": api_key,
    }

    data = {
        "query": "get_siginfo",
        "signature": family,
        "limit": QUERY_LIMIT,
    }

    response = requests.post(
        API_URL,
        headers=headers,
        data=data,
        timeout=60,
    )

    response.raise_for_status()

    result = response.json()

    status = result.get("query_status")

    if status != "ok":
        print(f"WARNING: {family}: query_status={status}")
        return []

    return result.get("data", [])


def is_pe(sample: dict) -> bool:
    file_type = (sample.get("file_type") or "").lower()
    mime = (sample.get("file_type_mime") or "").lower()

    return (
        file_type in {"exe", "dll"}
        or mime == "application/x-dosexec"
    )


def parse_date(value: str | None):
    if not value:
        return None

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass

    return None


def analyse_family(samples: list[dict], family: str) -> dict:
    unique = {}
    for sample in samples:
        sha256 = sample.get("sha256_hash")

        if sha256:
            unique[sha256] = sample

    unique_samples = list(unique.values())
    pe_samples = [s for s in unique_samples if is_pe(s)]

    exe_count = sum(
        (s.get("file_type") or "").lower() == "exe"
        for s in pe_samples
    )

    dll_count = sum(
        (s.get("file_type") or "").lower() == "dll"
        for s in pe_samples
    )

    signature_count = sum(
        bool(s.get("signature"))
        for s in pe_samples
    )

    first_seen_count = sum(
        bool(s.get("first_seen"))
        for s in pe_samples
    )

    imphash_count = sum(
        bool(s.get("imphash"))
        for s in pe_samples
    )

    tlsh_count = sum(
        bool(s.get("tlsh"))
        for s in pe_samples
    )

    ssdeep_count = sum(
        bool(s.get("ssdeep"))
        for s in pe_samples
    )

    dates = [
        parsed
        for parsed in (
            parse_date(s.get("first_seen"))
            for s in pe_samples
        )
        if parsed is not None
    ]

    earliest = min(dates).strftime("%Y-%m-%d") if dates else ""
    latest = max(dates).strftime("%Y-%m-%d") if dates else ""

    reporters = Counter(
        s.get("reporter")
        for s in pe_samples
        if s.get("reporter")
    )

    return {
        "family": family,
        "records_received": len(samples),
        "unique_sha256": len(unique_samples),
        "pe_count": len(pe_samples),
        "exe_count": exe_count,
        "dll_count": dll_count,
        "signature_present": signature_count,
        "first_seen_present": first_seen_count,
        "imphash_present": imphash_count,
        "tlsh_present": tlsh_count,
        "ssdeep_present": ssdeep_count,
        "earliest_first_seen": earliest,
        "latest_first_seen": latest,
        "unique_reporters": len(reporters),
    }


def main():
    api_key = load_api_key()

    print("=== MALWAREBAZAAR FAMILY AVAILABILITY AUDIT ===")
    print(f"Families: {len(FAMILIES)}")
    print(f"Query limit per family: {QUERY_LIMIT}")
    print("Download operation: DISABLED")
    print()

    results = []

    for index, family in enumerate(FAMILIES, start=1):
        print(
            f"[{index:02d}/{len(FAMILIES):02d}] "
            f"Querying {family}..."
        )

        samples = query_family(
            api_key=api_key,
            family=family,
        )

        result = analyse_family(samples, family)
        results.append(result)

        print(
            f"    records={result['records_received']} "
            f"unique={result['unique_sha256']} "
            f"PE={result['pe_count']} "
            f"EXE={result['exe_count']} "
            f"DLL={result['dll_count']}"
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = list(results[0].keys())

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(results)

    print()
    print("=== AUDIT COMPLETE ===")
    print(f"Output: {OUTPUT_FILE}")
    print()

    results.sort(
        key=lambda row: row["pe_count"],
        reverse=True,
    )

    print(
        f"{'Family':<16}"
        f"{'Records':>9}"
        f"{'Unique':>9}"
        f"{'PE':>9}"
        f"{'EXE':>9}"
        f"{'DLL':>9}"
    )
    print("-" * 61)

    for row in results:
        print(
            f"{row['family']:<16}"
            f"{row['records_received']:>9}"
            f"{row['unique_sha256']:>9}"
            f"{row['pe_count']:>9}"
            f"{row['exe_count']:>9}"
            f"{row['dll_count']:>9}"
        )


if __name__ == "__main__":
    main()
