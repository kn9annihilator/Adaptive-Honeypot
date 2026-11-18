import csv
import glob
import hashlib
import json
import os
import subprocess
import sys

CORPUS = "/srv/acquisition/quarantine"
EXTRACTOR = "/srv/acquisition/analysis/extract_pe_features.py"
OUTPUT = "/srv/acquisition/analysis/static_pe_features.csv"

records = {}

# Collect existing acquisition metadata
metadata_files = sorted(
    glob.glob("/srv/acquisition/metadata/batch_*.json")
    + glob.glob("/srv/acquisition/metadata/pilot_*.json")
)

for path in metadata_files:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

        if not raw.strip():
            continue

        data = json.loads(raw)
        items = data if isinstance(data, list) else [data]

        for r in items:
            if r.get("status") != "stored":
                continue

            sha = str(r.get("sha256", "")).strip().lower()
            family = str(r.get("family", "")).strip()

            if sha and sha not in records:
                records[sha] = family

    except Exception:
        continue

print("=" * 70)
print("FULL STATIC PE FEATURE EXTRACTION")
print("=" * 70)
print(f"Metadata stored identities : {len(records)}")

rows = []
failed = []

for i, (sha, family) in enumerate(sorted(records.items()), 1):

    sample = os.path.join(CORPUS, sha, "sample.bin")

    if not os.path.isfile(sample):
        failed.append((sha, family, "missing sample.bin"))
        continue

    size = os.path.getsize(sample)

    if size == 0:
        failed.append((sha, family, "zero-byte sample"))
        continue

    print(f"[{i}/{len(records)}] {family} {sha}", flush=True)

    result = subprocess.run(
        [
            sys.executable,
            EXTRACTOR,
            "--sample",
            sample,
            "--expected-sha",
            sha,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        failed.append(
            (
                sha,
                family,
                result.stderr.strip() or "extractor failed",
            )
        )
        continue

    features = {}

    # Parse extractor's "key : value" output
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if not key:
            continue

        if key in ("# STATIC PE FEATURE EXTRACTION",):
            continue

        features[key] = value

    if features.get("sha256", "").lower() != sha:
        failed.append((sha, family, "SHA mismatch in extractor output"))
        continue

    features["family"] = family
    rows.append(features)

# Write matrix
if rows:
    preferred = [
        "sha256",
        "file_size",
        "machine",
        "architecture",
        "number_of_sections",
        "timestamp",
        "characteristics",
        "entry_point",
        "image_base",
        "size_of_image",
        "size_of_headers",
        "subsystem",
        "dll_characteristics",
        "executable_sections",
        "readable_sections",
        "writable_sections",
        "total_raw_section_size",
        "total_virtual_section_size",
        "mean_section_entropy",
        "min_section_entropy",
        "max_section_entropy",
        "imported_dll_count",
        "imported_api_count",
        "unique_imported_api_count",
        "family",
    ]

    columns = []

    for c in preferred:
        if c in rows[0] and c not in columns:
            columns.append(c)

    for row in rows:
        for c in row:
            if c not in columns:
                columns.append(c)

    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

print("\n" + "=" * 70)
print("EXTRACTION SUMMARY")
print("=" * 70)
print(f"Metadata stored identities : {len(records)}")
print(f"Successfully extracted     : {len(rows)}")
print(f"Failed/skipped             : {len(failed)}")
print(f"Output                     : {OUTPUT}")

if failed:
    failure_file = OUTPUT.replace(".csv", "_failures.csv")

    with open(failure_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sha256", "family", "reason"])
        writer.writerows(failed)

    print(f"Failure report             : {failure_file}")

print("=" * 70)
