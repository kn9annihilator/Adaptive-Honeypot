#!/usr/bin/env python3

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler


BASE_DIR = Path("/srv/acquisition/analysis")
DATASET_DIR = BASE_DIR / "dataset"
FEATURE_DIR = BASE_DIR / "features"
PE_DIR = FEATURE_DIR / "pe"


NUMERIC_FEATURES = [
    "file_size",
    "number_of_sections",
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
]

CATEGORICAL_FEATURES = [
    "architecture",
]


def load_split(name):
    return pd.read_csv(
        DATASET_DIR / f"{name}.csv"
    )


def save_matrix(matrix, path):
    sparse.save_npz(path, matrix)


def main():

    print("=" * 70)
    print("PE FEATURE PREPROCESSING")
    print("=" * 70)

    PE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    train_df = load_split("train")
    validation_df = load_split("validation")
    test_df = load_split("test")

    feature_columns = (
        NUMERIC_FEATURES
        + CATEGORICAL_FEATURES
    )

    X_train = train_df[feature_columns]
    X_validation = validation_df[feature_columns]
    X_test = test_df[feature_columns]

    print()
    print("Input sizes:")
    print("Train       :", X_train.shape)
    print("Validation  :", X_validation.shape)
    print("Test        :", X_test.shape)

    print()
    print("Numerical features:", len(NUMERIC_FEATURES))
    print("Categorical features:", len(CATEGORICAL_FEATURES))

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                StandardScaler(),
                NUMERIC_FEATURES,
            ),
            (
                "architecture",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=True,
                    dtype=np.float32,
                ),
                CATEGORICAL_FEATURES,
            ),
        ],
        sparse_threshold=1.0,
    )

    print()
    print("Fitting preprocessing pipeline on TRAIN only...")

    X_train_transformed = preprocessor.fit_transform(
        X_train
    )

    print("Transforming validation...")
    X_validation_transformed = preprocessor.transform(
        X_validation
    )

    print("Transforming test...")
    X_test_transformed = preprocessor.transform(
        X_test
    )

    print()
    print("Output shapes:")
    print(
        "Train       :",
        X_train_transformed.shape,
    )
    print(
        "Validation  :",
        X_validation_transformed.shape,
    )
    print(
        "Test        :",
        X_test_transformed.shape,
    )

    print()
    print("Non-zero values:")
    print(
        "Train       :",
        X_train_transformed.nnz,
    )
    print(
        "Validation  :",
        X_validation_transformed.nnz,
    )
    print(
        "Test        :",
        X_test_transformed.nnz,
    )

    print()
    print("Architecture distribution:")
    print(
        train_df["architecture"]
        .value_counts()
        .sort_index()
        .to_string()
    )

    feature_names = (
        preprocessor
        .get_feature_names_out()
        .tolist()
    )

    feature_names_path = (
        PE_DIR / "feature_names.txt"
    )

    with open(
        feature_names_path,
        "w",
        encoding="utf-8",
    ) as f:
        for name in feature_names:
            f.write(name + "\n")

    save_matrix(
        X_train_transformed,
        PE_DIR / "train.npz",
    )

    save_matrix(
        X_validation_transformed,
        PE_DIR / "validation.npz",
    )

    save_matrix(
        X_test_transformed,
        PE_DIR / "test.npz",
    )

    preprocessor_path = (
        PE_DIR / "preprocessor.joblib"
    )

    joblib.dump(
        preprocessor,
        preprocessor_path,
    )

    manifest = {
        "fitting_policy": (
            "Numerical scaling and architecture encoding "
            "are fitted exclusively on the training split. "
            "Validation and test are transformed using "
            "the fitted training preprocessor."
        ),
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "excluded_features": [
            "sha256",
            "machine",
            "timestamp",
            "family",
            "SHA verification",
        ],
        "train_shape": list(
            X_train_transformed.shape
        ),
        "validation_shape": list(
            X_validation_transformed.shape
        ),
        "test_shape": list(
            X_test_transformed.shape
        ),
        "feature_count": len(feature_names),
    }

    manifest_path = (
        PE_DIR / "pe_feature_manifest.json"
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
    print("Saved:")
    print(preprocessor_path)
    print(PE_DIR / "train.npz")
    print(PE_DIR / "validation.npz")
    print(PE_DIR / "test.npz")
    print(feature_names_path)
    print(manifest_path)

    print()
    print("=" * 70)
    print("PE FEATURE PREPROCESSING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
