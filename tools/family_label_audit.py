import csv
import os
import sys
from pathlib import Path
from collections import Counter

import requests
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "bootstrap"
    / "MalwareBazaar"
    / "metadata"
    / "family_label_audit.csv"
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
    import time

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

                print(f"    Request error: {exc}")
                print(
                    f"    Retrying in {wait_seconds}s..."
                )

                time.sleep(wait_seconds)
            else:
                print(
                    f"    FAILED after {max_attempts} attempts: "
                    f"{exc}"
                )
                return []

    return []
def is_pe(sample):
    file_type = (sample.get("file_type") or "").lower()
    mime = (sample.get("file_type_mime") or "").lower()

    return (
        file_type in {"exe", "dll"}
        or mime == "application/x-dosexec"
    )


def analyse(family, samples):
    unique = {}

    for sample in samples:
        sha256 = sample.get("sha256_hash")

        if sha256:
            unique[sha256] = sample

    records = [
        sample
        for sample in unique.values()
        if is_pe(sample)
    ]

    signature_exact = 0
    signature_missing = 0
    signature_other = 0

    tag_contains_family = 0
    tag_missing = 0

    tag_conflicts = 0

    signatures = Counter()
    tag_values = Counter()

    for sample in records:
        signature = (
            sample.get("signature") or ""
        ).strip()

        if not signature:
            signature_missing += 1
        elif signature.lower() == family.lower():
            signature_exact += 1
        else:
            signature_other += 1

        signatures[signature] += 1

        tags = sample.get("tags") or []

        if not tags:
            tag_missing += 1
        else:
            normalized_tags = {
                str(tag).strip().lower()
                for tag in tags
                if str(tag).strip()
            }

            if family.lower() in normalized_tags:
                tag_contains_family += 1

            family_like_tags = {
                tag
                for tag in normalized_tags
                if tag not in {
                    "exe",
                    "dll",
                    "pe",
                    "windows",
                    "malware",
                }
            }

            if (
                family.lower() not in family_like_tags
                and family.lower() in normalized_tags
            ):
                tag_conflicts += 0

            for tag in normalized_tags:
                tag_values[tag] += 1

    return {
        "family": family,
        "pe_samples": len(records),
        "signature_exact": signature_exact,
        "signature_missing": signature_missing,
        "signature_other": signature_other,
        "tag_contains_family": tag_contains_family,
        "tag_missing": tag_missing,
        "unique_signatures": len(signatures),
        "unique_tags": len(tag_values),
    }


def main():
    api_key = load_api_key()

    print("=== FAMILY LABEL CONSISTENCY AUDIT ===")
    print("Metadata only")
    print("Downloads disabled")
    print()

    results = []

    for index, family in enumerate(FAMILIES, 1):
        print(
            f"[{index:02d}/{len(FAMILIES):02d}] "
            f"{family}"
        )

        samples = query_family(
            api_key,
            family,
        )

        result = analyse(
            family,
            samples,
        )

        results.append(result)

        print(
            f"    PE={result['pe_samples']} "
            f"exact_signature={result['signature_exact']} "
            f"missing={result['signature_missing']} "
            f"other={result['signature_other']}"
        )

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
    print("=== LABEL AUDIT COMPLETE ===")
    print(f"Output: {OUTPUT_FILE}")
    print()

    for result in results:
        print(
            f"{result['family']:<16} "
            f"PE={result['pe_samples']:<4} "
            f"exact={result['signature_exact']:<4} "
            f"missing={result['signature_missing']:<4} "
            f"other={result['signature_other']:<4} "
            f"tags_with_family={result['tag_contains_family']:<4} "
            f"unique_signatures={result['unique_signatures']:<3}"
        )


if __name__ == "__main__":
    main()
