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
    / "family_metadata_quality.csv"
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

    api_key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

    if not api_key:
        print("ERROR: MALWAREBAZAAR_AUTH_KEY is not set in .env")
        sys.exit(1)

    return api_key


def query_family(api_key, family):
    response = requests.post(
        API_URL,
        headers={"Auth-Key": api_key},
        data={
            "query": "get_siginfo",
            "signature": family,
            "limit": QUERY_LIMIT,
        },
        timeout=60,
    )

    response.raise_for_status()

    result = response.json()

    if result.get("query_status") != "ok":
        print(
            f"WARNING: {family}: "
            f"{result.get('query_status')}"
        )
        return []

    return result.get("data", [])


def is_pe(sample):
    file_type = (sample.get("file_type") or "").lower()
    mime = (sample.get("file_type_mime") or "").lower()

    return (
        file_type in {"exe", "dll"}
        or mime == "application/x-dosexec"
    )


def present(sample, field):
    value = sample.get(field)

    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    return True


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

    fields = {
        "sha256": "sha256_hash",
        "sha1": "sha1_hash",
        "md5": "md5_hash",
        "filename": "file_name",
        "size": "file_size",
        "file_type": "file_type",
        "file_format": "file_format",
        "architecture": "file_arch",
        "first_seen": "first_seen",
        "signature": "signature",
        "imphash": "imphash",
        "tlsh": "tlsh",
        "ssdeep": "ssdeep",
        "reporter": "reporter",
        "tags": "tags",
    }

    result = {
        "family": family,
        "pe_samples": len(records),
    }

    for name, field in fields.items():
        count = sum(
            present(sample, field)
            for sample in records
        )

        result[f"{name}_present"] = count

        if records:
            result[f"{name}_pct"] = round(
                count * 100 / len(records),
                2,
            )
        else:
            result[f"{name}_pct"] = 0.0

    return result


def main():
    api_key = load_api_key()

    print("=== FAMILY METADATA QUALITY AUDIT ===")
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

        result = analyse(
            family,
            samples,
        )

        results.append(result)

        print(
            f"    PE={result['pe_samples']} "
            f"SHA256={result['sha256_pct']}% "
            f"first_seen={result['first_seen_pct']}% "
            f"imphash={result['imphash_pct']}%"
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
    print("=== METADATA QUALITY AUDIT COMPLETE ===")
    print(f"Output: {OUTPUT_FILE}")
    print()

    for result in results:
        print(
            f"{result['family']:<16} "
            f"PE={result['pe_samples']:<4} "
            f"SHA256={result['sha256_pct']:>6}% "
            f"SHA1={result['sha1_pct']:>6}% "
            f"MD5={result['md5_pct']:>6}% "
            f"filename={result['filename_pct']:>6}% "
            f"size={result['size_pct']:>6}% "
            f"type={result['file_type_pct']:>6}% "
            f"format={result['file_format_pct']:>6}% "
            f"arch={result['architecture_pct']:>6}% "
            f"first_seen={result['first_seen_pct']:>6}% "
            f"signature={result['signature_pct']:>6}% "
            f"imphash={result['imphash_pct']:>6}% "
            f"tlsh={result['tlsh_pct']:>6}% "
            f"ssdeep={result['ssdeep_pct']:>6}%"
        )


if __name__ == "__main__":
    main()
