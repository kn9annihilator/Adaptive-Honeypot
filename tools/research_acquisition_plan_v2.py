from __future__ import annotations

import csv
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv


# ============================================================================
# Project paths
# ============================================================================

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent

CORPUS_ROOT = PROJECT_ROOT.parent / "Corpus"
CORPUS_MANIFEST = CORPUS_ROOT / "manifests" / "samples.jsonl"

OUTPUT_DIR = (
    PROJECT_ROOT
    / "Dataset"
    / "bootstrap"
    / "MalwareBazaar"
    / "metadata"
)

# v2 output: NEVER overwrite v1.
OUTPUT_CSV = OUTPUT_DIR / "acquisition_plan_v2.csv"
OUTPUT_JSON = OUTPUT_DIR / "acquisition_plan_v2_summary.json"

# Frozen v1 plan used only as a fallback for unresolved families.
V1_PLAN_CSV = OUTPUT_DIR / "acquisition_plan.csv"

API_URL = "https://mb-api.abuse.ch/api/v1/"


# ============================================================================
# Research cohort
# ============================================================================

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


# Primary targets for acquisition_plan_v2.
#
# These are intentionally adaptive:
# - Emotet is constrained to 94 because the validated PE availability
#   indicated 95 PE records, with one already represented in the corpus.
# - Most sufficiently available families are raised to 150.
# - FormBook and AgentTesla remain at their validated v1 baseline because
#   their MalwareBazaar signature queries currently time out.
# - XWorm is constrained to 122 by the observed PE availability.
FAMILY_TARGETS = {
    "Emotet": 94,
    "NanoCore": 150,
    "njRAT": 150,
    "BitRAT": 150,
    "AsyncRAT": 150,
    "Dridex": 150,
    "TrickBot": 150,
    "FormBook": 100,
    "DarkComet": 150,
    "IcedID": 150,
    "AgentTesla": 100,
    "XWorm": 122,
}


# Approximately 20% reserve.
RESERVE_FACTOR = 0.20

QUERY_LIMIT = 1000
REQUEST_TIMEOUT = (15, 60)
MAX_RETRIES = 4


# ============================================================================
# API
# ============================================================================

def load_api_key() -> str:
    """Load the MalwareBazaar API key from the project .env file."""

    load_dotenv(PROJECT_ROOT / ".env")

    key = os.getenv("MALWAREBAZAAR_AUTH_KEY")

    if not key:
        raise RuntimeError(
            "MALWAREBAZAAR_AUTH_KEY was not found in the project .env file."
        )

    return key


def query_family(api_key: str, family: str) -> list[dict]:
    """
    Query MalwareBazaar metadata for one malware family.

    This function is metadata-only. It never downloads malware.
    """

    headers = {
        "Auth-Key": api_key,
        "User-Agent": "Adaptive-Honeypot-Research-Acquisition-Planner",
    }

    payload = {
        "query": "get_siginfo",
        "signature": family,
        "limit": QUERY_LIMIT,
    }

    last_error: Exception | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(
                API_URL,
                headers=headers,
                data=payload,
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code in {502, 503, 504}:
                last_error = RuntimeError(
                    f"HTTP {response.status_code}"
                )

                if attempt < MAX_RETRIES:
                    continue

                raise last_error

            response.raise_for_status()

            data = response.json()

            if data.get("query_status") != "ok":
                raise RuntimeError(
                    f"{family}: unexpected query_status="
                    f"{data.get('query_status')!r}"
                )

            records = data.get("data", [])

            if not isinstance(records, list):
                raise RuntimeError(
                    f"{family}: MalwareBazaar returned non-list data"
                )

            return records

        except (requests.RequestException, ValueError, RuntimeError) as exc:
            last_error = exc

            if attempt == MAX_RETRIES:
                break

    raise RuntimeError(
        f"Failed querying MalwareBazaar for {family}: {last_error}"
    )


# ============================================================================
# Corpus identity
# ============================================================================

def load_existing_corpus_hashes() -> set[str]:
    """
    Load SHA-256 identities already present in the canonical corpus.

    Invalid JSONL records are ignored, matching the v1 planner behavior.
    """

    hashes: set[str] = set()

    if not CORPUS_MANIFEST.exists():
        return hashes

    with CORPUS_MANIFEST.open(
        "r",
        encoding="utf-8",
    ) as handle:
        for line in handle:
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            identity = record.get("identity", {})

            sha256 = str(
                identity.get("sha256", "")
            ).lower().strip()

            if len(sha256) == 64:
                hashes.add(sha256)

    return hashes


# ============================================================================
# v1 fallback
# ============================================================================

def load_v1_family_candidates(
    plan_path: Path,
    family: str,
) -> list[dict]:
    """
    Load already-normalized candidate rows for one family from the
    frozen v1 acquisition plan.

    This function does NOT query MalwareBazaar and does NOT invent
    availability. It simply reuses the validated v1 candidate pool.

    The returned rows already use the planner's normalized CSV schema,
    so they must NOT be passed through normalize_candidate().
    """

    if not plan_path.exists():
        raise RuntimeError(
            f"Frozen v1 acquisition plan does not exist: {plan_path}"
        )

    rows: list[dict] = []

    with plan_path.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        reader = csv.DictReader(handle)

        for row in reader:
            if (row.get("family") or "").strip() == family:
                rows.append(dict(row))

    if not rows:
        raise RuntimeError(
            f"No existing v1 candidates found for unresolved family: {family}"
        )

    return rows


# ============================================================================
# Candidate validation
# ============================================================================

def is_valid_sha256(value: str | None) -> bool:
    """Return True only for a valid 64-character hexadecimal SHA-256."""

    if not value:
        return False

    value = value.strip().lower()

    if len(value) != 64:
        return False

    return all(
        character in "0123456789abcdef"
        for character in value
    )


def is_pe_candidate(sample: dict) -> bool:
    """
    Determine whether a candidate is a PE using the same logic as v1.
    """

    file_type = str(
        sample.get("file_type") or ""
    ).lower()

    mime = str(
        sample.get("file_type_mime")
        or sample.get("mime_type")
        or ""
    ).lower()

    file_format = str(
        sample.get("file_format") or ""
    ).lower()

    if file_type in {"exe", "dll"}:
        return True

    if "dosexec" in mime:
        return True

    if file_format == "pe":
        return True

    return False


def parse_first_seen(sample: dict) -> datetime | None:
    """Parse MalwareBazaar first_seen values for deterministic sorting."""

    value = sample.get("first_seen")

    if not value:
        return None

    value = str(value).strip()

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    )

    for fmt in formats:
        try:
            return datetime.strptime(
                value,
                fmt,
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return None


# ============================================================================
# Candidate normalization
# ============================================================================

def normalize_candidate(
    sample: dict,
    family: str,
) -> dict:
    """
    Convert a raw MalwareBazaar API record into the planner schema.
    """

    return {
        "sha256": str(
            sample.get("sha256_hash") or ""
        ).lower().strip(),

        "sha1": str(
            sample.get("sha1_hash") or ""
        ).lower().strip(),

        "md5": str(
            sample.get("md5_hash") or ""
        ).lower().strip(),

        "family": family,

        "signature": str(
            sample.get("signature") or ""
        ).strip(),

        "tags": json.dumps(
            sample.get("tags") or [],
            separators=(",", ":"),
        ),

        "file_name": str(
            sample.get("file_name") or ""
        ).strip(),

        "file_size": str(
            sample.get("file_size") or ""
        ).strip(),

        "file_type": str(
            sample.get("file_type") or ""
        ).strip(),

        "file_format": str(
            sample.get("file_format") or ""
        ).strip(),

        "file_arch": str(
            sample.get("file_arch") or ""
        ).strip(),

        "first_seen": str(
            sample.get("first_seen") or ""
        ).strip(),

        "last_seen": str(
            sample.get("last_seen") or ""
        ).strip(),

        "reporter": str(
            sample.get("reporter") or ""
        ).strip(),

        "imphash": str(
            sample.get("imphash") or ""
        ).strip(),

        "tlsh": str(
            sample.get("tlsh") or ""
        ).strip(),

        "ssdeep": str(
            sample.get("ssdeep") or ""
        ).strip(),

        "source": "MalwareBazaar",
        "acquisition_provenance": "bootstrap",
        "dataset_role": "unassigned",
        "label_status": "dataset_provided",
        "selection_status": "candidate",
        "exclusion_reason": "",
    }


# ============================================================================
# Selection
# ============================================================================

def select_candidates(
    candidates_by_family: dict[str, list[dict]],
    existing_hashes: set[str],
) -> tuple[
    list[dict],
    Counter,
    dict[str, Counter],
    dict[str, dict[str, int]],
]:
    """
    Select primary and reserve candidates.

    Selection is:
    1. SHA-256 valid
    2. signature matches requested family
    3. PE
    4. not already in canonical corpus
    5. not duplicated elsewhere in the planned cohort
    6. deterministic by first_seen then SHA-256
    """

    selected: list[dict] = []

    global_hashes: set[str] = set(existing_hashes)

    exclusion_counts: Counter = Counter()

    family_exclusions: dict[str, Counter] = (
        defaultdict(Counter)
    )

    family_results: dict[str, dict[str, int]] = {}

    for family in FAMILIES:
        target = FAMILY_TARGETS[family]

        pool = candidates_by_family.get(
            family,
            [],
        )

        valid: list[dict] = []

        for row in pool:
            sha256 = (
                str(row.get("sha256") or "")
                .lower()
                .strip()
            )

            if not is_valid_sha256(sha256):
                exclusion_counts["invalid_sha256"] += 1
                family_exclusions[family][
                    "invalid_sha256"
                ] += 1
                continue

            row["sha256"] = sha256

            signature = str(
                row.get("signature") or ""
            ).strip()

            if signature.lower() != family.lower():
                exclusion_counts["signature_mismatch"] += 1
                family_exclusions[family][
                    "signature_mismatch"
                ] += 1
                continue

            if not is_pe_candidate(row):
                exclusion_counts["non_pe"] += 1
                family_exclusions[family][
                    "non_pe"
                ] += 1
                continue

            if sha256 in global_hashes:
                if sha256 in existing_hashes:
                    reason = "already_in_corpus"
                else:
                    reason = "duplicate_sha256"

                exclusion_counts[reason] += 1
                family_exclusions[family][reason] += 1
                continue

            valid.append(row)

        # Deterministic ordering:
        # earliest first_seen, then SHA-256.
        valid.sort(
            key=lambda row: (
                parse_first_seen(row)
                or datetime.max.replace(
                    tzinfo=timezone.utc
                ),
                row["sha256"],
            )
        )

        # ---------------------------------------------------------------
        # Primary selection
        # ---------------------------------------------------------------

        primary_target = min(
            target,
            len(valid),
        )

        primary_rows = valid[:primary_target]

        for row in primary_rows:
            row["selection_status"] = "primary"
            selected.append(row)
            global_hashes.add(row["sha256"])

        # ---------------------------------------------------------------
        # Reserve selection
        # ---------------------------------------------------------------

        reserve_target = max(
            0,
            round(target * RESERVE_FACTOR),
        )

        remaining = valid[primary_target:]

        reserve_rows = remaining[:reserve_target]

        for row in reserve_rows:
            row["selection_status"] = "reserve"
            selected.append(row)
            global_hashes.add(row["sha256"])

        family_results[family] = {
            "eligible": len(valid),
            "primary_target": target,
            "primary_selected": len(primary_rows),
            "reserve_target": reserve_target,
            "reserve_selected": len(reserve_rows),
        }

    return (
        selected,
        exclusion_counts,
        family_exclusions,
        family_results,
    )


# ============================================================================
# Output
# ============================================================================

CSV_FIELDS = [
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
    "acquisition_provenance",
    "dataset_role",
    "label_status",
    "selection_status",
    "exclusion_reason",
]


def write_csv(rows: list[dict]) -> None:
    """Write the v2 acquisition plan CSV."""

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_CSV.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_FIELDS,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)


def write_summary(
    rows: list[dict],
    queried_counts: dict[str, int],
    fallback_families: list[str],
    exclusion_counts: Counter,
    family_exclusions: dict[str, Counter],
    family_results: dict[str, dict[str, int]],
) -> None:
    """Write the v2 planner summary JSON."""

    primary_total = sum(
        1
        for row in rows
        if row["selection_status"] == "primary"
    )

    reserve_total = sum(
        1
        for row in rows
        if row["selection_status"] == "reserve"
    )

    family_counts: dict[str, dict[str, int]] = {}

    for family in FAMILIES:
        family_rows = [
            row
            for row in rows
            if row["family"] == family
        ]

        family_counts[family] = {
            "primary": sum(
                row["selection_status"] == "primary"
                for row in family_rows
            ),
            "reserve": sum(
                row["selection_status"] == "reserve"
                for row in family_rows
            ),
        }

    temporal_counts: dict[str, Counter] = {
        family: Counter()
        for family in FAMILIES
    }

    for row in rows:
        first_seen = parse_first_seen(row)

        if first_seen:
            temporal_counts[
                row["family"]
            ][str(first_seen.year)] += 1
        else:
            temporal_counts[
                row["family"]
            ]["unknown"] += 1

    summary = {
        "planner_version": "2.0",
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "mode": "metadata_only",
        "downloads_performed": False,
        "sample_execution": False,

        "api": {
            "endpoint": API_URL,
            "query": "get_siginfo",
            "query_limit": QUERY_LIMIT,
            "max_retries": MAX_RETRIES,
        },

        "selection_policy": {
            "reserve_factor": RESERVE_FACTOR,
            "primary_targets": FAMILY_TARGETS,
            "reserve_is_availability_bounded": True,
            "existing_corpus_excluded": True,
            "sha256_deduplication": True,
            "family_signature_must_match": True,
            "pe_required": True,
            "dataset_role_assigned": False,
        },

        "fallback_policy": {
            "enabled": True,
            "families": sorted(fallback_families),
            "source": str(V1_PLAN_CSV),
            "metadata_only": True,
            "availability_invented": False,
        },

        "results": {
            "primary_total": primary_total,
            "reserve_total": reserve_total,
            "planned_total": len(rows),

            "family_counts": family_counts,

            "family_selection_details": family_results,

            "queried_counts": dict(
                sorted(queried_counts.items())
            ),

            "temporal_counts": {
                family: dict(
                    sorted(counts.items())
                )
                for family, counts in sorted(
                    temporal_counts.items()
                )
            },
        },

        "exclusions": {
            "global": dict(
                sorted(
                    exclusion_counts.items()
                )
            ),

            "by_family": {
                family: dict(
                    sorted(counts.items())
                )
                for family, counts in sorted(
                    family_exclusions.items()
                )
            },
        },

        "provenance": {
            "acquisition_provenance": "bootstrap",
            "dataset_role": "unassigned",
            "label_status": "dataset_provided",
        },

        "corpus_manifest": str(
            CORPUS_MANIFEST
        ),

        "v1_plan": str(
            V1_PLAN_CSV
        ),

        "v2_plan": str(
            OUTPUT_CSV
        ),
    }

    with OUTPUT_JSON.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            summary,
            handle,
            indent=2,
        )

        handle.write("\n")


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    print(
        "=== Phase 4 Research Acquisition Planner v2 ==="
    )

    print("Mode: METADATA ONLY")
    print("Downloads: DISABLED")
    print("Execution: DISABLED")
    print()

    # Safety assertion: v2 must never point to the v1 output.
    if OUTPUT_CSV == V1_PLAN_CSV:
        raise RuntimeError(
            "Safety failure: v2 CSV path equals the v1 CSV path."
        )

    if OUTPUT_JSON == OUTPUT_DIR / "acquisition_plan_summary.json":
        raise RuntimeError(
            "Safety failure: v2 JSON path equals the v1 summary path."
        )

    api_key = load_api_key()

    existing_hashes = load_existing_corpus_hashes()

    print(
        "Existing canonical corpus SHA-256 "
        f"identities: {len(existing_hashes)}"
    )

    candidates_by_family: dict[str, list[dict]] = {}

    queried_counts: dict[str, int] = {}

    fallback_families: list[str] = []

    for index, family in enumerate(
        FAMILIES,
        start=1,
    ):
        print(
            f"[{index:02d}/{len(FAMILIES):02d}] "
            f"Querying metadata: {family}"
        )

        try:
            raw_samples = query_family(
                api_key,
                family,
            )

            queried_counts[family] = len(
                raw_samples
            )

            normalized = [
                normalize_candidate(
                    sample,
                    family,
                )
                for sample in raw_samples
            ]

        except RuntimeError as exc:
            # Only the two previously diagnosed families are allowed
            # to use the frozen v1 fallback.
            if family not in {
                "FormBook",
                "AgentTesla",
            }:
                raise

            print(
                f"       WARNING: {family} metadata query unavailable."
            )
            print(
                "       Retaining validated v1 candidate pool."
            )
            print(
                f"       Reason: {exc}"
            )

            fallback_rows = load_v1_family_candidates(
                V1_PLAN_CSV,
                family,
            )

            fallback_families.append(family)

            queried_counts[family] = len(
                fallback_rows
            )

            # IMPORTANT:
            # v1 rows are already normalized to CSV_FIELDS.
            # Do NOT pass them through normalize_candidate().
            normalized = fallback_rows

        candidates_by_family[family] = normalized

        pe_count = sum(
            is_pe_candidate(row)
            for row in normalized
        )

        print(
            f"       records={len(normalized)} "
            f"PE={pe_count} "
            f"target={FAMILY_TARGETS[family]}"
        )

    print()
    print(
        "Selecting primary and reserve candidates..."
    )

    (
        selected,
        exclusion_counts,
        family_exclusions,
        family_results,
    ) = select_candidates(
        candidates_by_family,
        existing_hashes,
    )

    write_csv(selected)

    write_summary(
        selected,
        queried_counts,
        fallback_families,
        exclusion_counts,
        family_exclusions,
        family_results,
    )

    print()
    print(
        "===== SELECTION RESULT ====="
    )

    print(
        f"{'Family':<12}"
        f"{'Primary':>9}"
        f"{'Reserve':>9}"
        f"{'Eligible':>10}"
    )

    print("-" * 42)

    for family in FAMILIES:
        result = family_results[family]

        print(
            f"{family:<12}"
            f"{result['primary_selected']:>9}"
            f"{result['reserve_selected']:>9}"
            f"{result['eligible']:>10}"
        )

    primary_total = sum(
        result["primary_selected"]
        for result in family_results.values()
    )

    reserve_total = sum(
        result["reserve_selected"]
        for result in family_results.values()
    )

    print()
    print(
        f"Primary total : {primary_total}"
    )

    print(
        f"Reserve total : {reserve_total}"
    )

    print(
        f"Planned total : {len(selected)}"
    )

    print()
    print(
        f"CSV: {OUTPUT_CSV}"
    )

    print(
        f"JSON: {OUTPUT_JSON}"
    )

    print()
    print(
        "No malware was downloaded."
    )

    print(
        "No malware was executed."
    )

    if fallback_families:
        print()
        print(
            "v1 fallback families:"
        )

        for family in fallback_families:
            print(
                f"  - {family}"
            )

    shortfalls = [
        family
        for family in FAMILIES
        if family_results[family][
            "primary_selected"
        ] < FAMILY_TARGETS[family]
    ]

    if shortfalls:
        print()
        print(
            "WARNING: Primary family shortfall:"
        )

        for family in shortfalls:
            result = family_results[family]

            print(
                f"  - {family}: "
                f"{result['primary_selected']}/"
                f"{result['primary_target']}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())