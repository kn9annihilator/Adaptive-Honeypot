from __future__ import annotations

import csv
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent

PLAN_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "bootstrap"
    / "MalwareBazaar"
    / "metadata"
    / "acquisition_plan.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "Dataset"
    / "bootstrap"
    / "MalwareBazaar"
    / "metadata"
    / "primary_acquisition.csv"
)

EXPECTED_PRIMARY_COUNT = 1194

OUTPUT_FIELDS = [
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


def main() -> None:
    if not PLAN_FILE.exists():
        raise FileNotFoundError(
            f"Acquisition plan not found: {PLAN_FILE}"
        )

    primary_rows: list[dict[str, str]] = []
    seen_sha256: set[str] = set()

    with PLAN_FILE.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        reader = csv.DictReader(handle)

        required = {
            "sha256",
            "family",
            "signature",
            "acquisition_provenance",
            "dataset_role",
            "label_status",
            "selection_status",
        }

        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                "Acquisition plan is missing required fields: "
                + ", ".join(sorted(missing))
            )

        for row in reader:
            status = (
                row.get("selection_status") or ""
            ).strip().lower()

            if status != "primary":
                continue

            sha256 = (
                row.get("sha256") or ""
            ).strip().lower()

            if len(sha256) != 64:
                raise ValueError(
                    f"Invalid SHA-256 for primary sample: {sha256}"
                )

            if sha256 in seen_sha256:
                raise ValueError(
                    f"Duplicate SHA-256 in primary plan: {sha256}"
                )

            seen_sha256.add(sha256)

            provenance = (
                row.get("acquisition_provenance") or ""
            ).strip().lower()

            if provenance != "bootstrap":
                raise ValueError(
                    f"Unexpected acquisition provenance for {sha256}: "
                    f"{provenance}"
                )

            dataset_role = (
                row.get("dataset_role") or ""
            ).strip().lower()

            if dataset_role != "unassigned":
                raise ValueError(
                    f"Unexpected dataset role for {sha256}: "
                    f"{dataset_role}"
                )

            output_row = {
                field: row.get(field, "")
                for field in OUTPUT_FIELDS
            }

            output_row["sha256"] = sha256
            output_row["selected"] = "pending"
            output_row["exclusion_reason"] = ""
            output_row["dataset_split"] = ""

            primary_rows.append(output_row)

    if len(primary_rows) != EXPECTED_PRIMARY_COUNT:
        raise ValueError(
            "Primary acquisition count mismatch: "
            f"expected {EXPECTED_PRIMARY_COUNT}, "
            f"found {len(primary_rows)}"
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
            fieldnames=OUTPUT_FIELDS,
        )
        writer.writeheader()
        writer.writerows(primary_rows)

    print(
        f"Primary acquisition manifest created: {OUTPUT_FILE}"
    )
    print(
        f"Primary records: {len(primary_rows)}"
    )
    print(
        f"Unique SHA-256 values: {len(seen_sha256)}"
    )
    print(
        "Reserve records excluded: "
        "selection_status != primary"
    )
    print(
        "Malware downloaded: 0"
    )


if __name__ == "__main__":
    main()