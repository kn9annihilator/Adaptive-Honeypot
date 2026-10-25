#!/usr/bin/env python3

from pathlib import Path
import json

import numpy as np
from scipy import sparse


BASE_DIR = Path("/srv/acquisition/analysis")
FEATURE_DIR = BASE_DIR / "features"
COMBINED_DIR = FEATURE_DIR / "combined"


REPRESENTATIONS = {
    "pe": FEATURE_DIR / "pe",
    "dll": FEATURE_DIR / "dll",
    "api": FEATURE_DIR / "api",
}


SPLITS = [
    "train",
    "validation",
    "test",
]


COMBINATIONS = {
    "pe_dll": ["pe", "dll"],
    "pe_api": ["pe", "api"],
    "pe_dll_api": ["pe", "dll", "api"],
}


def load_matrix(rep, split):
    path = REPRESENTATIONS[rep] / f"{split}.npz"

    if not path.exists():
        raise FileNotFoundError(path)

    return sparse.load_npz(path)


def main():

    print("=" * 70)
    print("COMBINED FEATURE REPRESENTATIONS")
    print("=" * 70)

    COMBINED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    manifest = {
        "representations": {}
    }

    for combination_name, components in COMBINATIONS.items():

        print()
        print("=" * 70)
        print(combination_name.upper())
        print("=" * 70)

        output_dir = COMBINED_DIR / combination_name
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        manifest["representations"][combination_name] = {
            "components": components,
            "splits": {}
        }

        for split in SPLITS:

            matrices = [
                load_matrix(rep, split)
                for rep in components
            ]

            rows = {
                matrix.shape[0]
                for matrix in matrices
            }

            if len(rows) != 1:
                raise ValueError(
                    f"Row mismatch in {combination_name}/{split}"
                )

            combined = sparse.hstack(
                matrices,
                format="csr",
            )

            output_path = output_dir / f"{split}.npz"

            sparse.save_npz(
                output_path,
                combined,
            )

            manifest["representations"][
                combination_name
            ]["splits"][split] = {
                "shape": list(combined.shape),
                "nnz": int(combined.nnz),
                "density": float(
                    combined.nnz
                    / (
                        combined.shape[0]
                        * combined.shape[1]
                    )
                ),
                "path": str(output_path),
            }

            print(
                f"{split:12} : "
                f"{combined.shape} | "
                f"nnz={combined.nnz}"
            )

    manifest_path = (
        FEATURE_DIR
        / "combined_feature_manifest.json"
    )

    with open(
        manifest_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            manifest,
            f,
            indent=2,
        )

    print()
    print("Manifest:")
    print(manifest_path)

    print()
    print("=" * 70)
    print("COMBINED FEATURE REPRESENTATIONS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
