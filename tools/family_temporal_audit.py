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
    / "family_temporal_audit.csv"
)

API_URL = "https://mb-api.abuse.ch/api/v1/"

FAMILIES = [
    "Emotet",
    "NanoCore",
    "njRAT",
    "BitRAT",
    "AsyncRAT",
    "Dridex",
    "TrickBot",
    "FormBook",
    "DarkComet",
    "IcedID",
    "AgentTesla",
    "XWorm",
]

QUERY_LIMIT = 1000


def load_api_key():
    load_dotenv(PROJECT_ROOT / ".env")

    key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

    if not key:
        print("ERROR: MALWAREBAZAAR_AUTH_KEY is not set in .env")
        sys.exit(1)

    return key


def query_family(api_key, family):
    headers = {
        "Auth-Key": api_key,
    }

    data = {
        "query": "get_siginfo",
        "signature": family,
        "limit": QUERY_LIMIT,
    }

    max_attempts = 4

    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.post(
                API_URL,
                headers=headers,
                data=data,
                timeout=60,
            )

            if response.status_code in {502, 503, 504}:
                if attempt < max_attempts:
                    wait_seconds = 2 ** (attempt - 1)
                    print(
                        f"    HTTP {response.status_code}; "
                        f"retrying in {wait_seconds}s..."
                    )

                    import time
                    time.sleep(wait_seconds)
                    continue

                print(
                    f"    FAILED: HTTP {response.status_code} "
                    f"after {max_attempts} attempts"
                )
                return []

            response.raise_for_status()

            result = response.json()

            if result.get("query_status") != "ok":
                print(
                    f"    WARNING: query_status="
                    f"{result.get('query_status')}"
                )
                return []

            return result.get("data", [])

        except requests.RequestException as exc:
            if attempt < max_attempts:
                wait_seconds = 2 ** (attempt - 1)

                print(
                    f"    Request error: {exc}"
                )
                print(
                    f"    Retrying in {wait_seconds}s..."
                )

                import time
                time.sleep(wait_seconds)
            else:
                print(
                    f"    FAILED after {max_attempts} attempts: "
                    f"{exc}"
                )
                return []

    return []


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


def analyse(family, samples):
    unique = {}

    for sample in samples:
        sha256 = sample.get("sha256_hash")

        if sha256:
            unique[sha256] = sample

    samples = [
        sample
        for sample in unique.values()
        if is_pe(sample)
    ]

    dates = [
        parse_date(sample.get("first_seen"))
        for sample in samples
    ]

    dates = [date for date in dates if date]

    years = Counter(date.year for date in dates)

    months = Counter(
        date.strftime("%Y-%m")
        for date in dates
    )

    return {
        "family": family,
        "pe_samples": len(samples),
        "dates_present": len(dates),
        "unique_years": len(years),
        "earliest": (
            min(dates).strftime("%Y-%m-%d")
            if dates else ""
        ),
        "latest": (
            max(dates).strftime("%Y-%m-%d")
            if dates else ""
        ),
        "year_distribution": ";".join(
            f"{year}:{count}"
            for year, count in sorted(years.items())
        ),
        "month_count": len(months),
    }


def main():
    api_key = load_api_key()

    print("=== FAMILY TEMPORAL AUDIT ===")
    print("Metadata only")
    print("Downloads disabled")
    print()

    results = []

    for index, family in enumerate(FAMILIES, 1):
        print(
            f"[{index:02d}/{len(FAMILIES):02d}] "
            f"{family}"
        )

        samples = query_family(api_key, family)
        results.append(analyse(family, samples))

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=results[0].keys(),
        )
        writer.writeheader()
        writer.writerows(results)

    print()
    print("=== TEMPORAL AUDIT COMPLETE ===")
    print(f"Output: {OUTPUT_FILE}")
    print()

    for result in results:
        print(
            f"{result['family']:<16} "
            f"PE={result['pe_samples']:<4} "
            f"Years={result['unique_years']:<3} "
            f"Months={result['month_count']:<4} "
            f"{result['earliest']} -> "
            f"{result['latest']}"
        )

        print(
            f"    {result['year_distribution']}"
        )


if __name__ == "__main__":
    main()