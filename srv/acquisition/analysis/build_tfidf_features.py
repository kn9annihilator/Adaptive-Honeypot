from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer


BASE_DIR = Path("/srv/acquisition/analysis")
DATASET_DIR = BASE_DIR / "dataset"
FEATURE_DIR = BASE_DIR / "features"

TFIDF_DIR = FEATURE_DIR / "tfidf"
DLL_DIR = FEATURE_DIR / "dll"
API_DIR = FEATURE_DIR / "api"

RANDOM_STATE = 42


def load_split(name):
    path = DATASET_DIR / f"{name}.csv"
    return pd.read_csv(path)


def tokenize_imports(text):
    if not isinstance(text, str):
        return []

    text = text.strip()

    if not text:
        return []

    return [token for token in text.split("|") if token]


def build_vectorizer():
    return TfidfVectorizer(
        tokenizer=tokenize_imports,
        preprocessor=None,
        token_pattern=None,
        lowercase=False,
        ngram_range=(1, 1),
        min_df=1,
        max_df=1.0,
        sublinear_tf=True,
        norm="l2",
        dtype=np.float32,
    )


def save_matrix(matrix, path):
    sparse.save_npz(path, matrix)


def process_feature(
    feature_name,
    train_df,
    validation_df,
    test_df,
):
    print()
    print("=" * 70)
    print(f"{feature_name.upper()} TF-IDF")
    print("=" * 70)

    vectorizer = build_vectorizer()

    train_text = train_df[feature_name].fillna("")
    validation_text = validation_df[feature_name].fillna("")
    test_text = test_df[feature_name].fillna("")

    print("Fitting vectorizer on TRAIN only...")

    train_matrix = vectorizer.fit_transform(train_text)

    print("Transforming validation...")
    validation_matrix = vectorizer.transform(validation_text)

    print("Transforming test...")
    test_matrix = vectorizer.transform(test_text)

    vocabulary_size = len(vectorizer.vocabulary_)

    print()
    print("Vocabulary size :", vocabulary_size)
    print("Train shape     :", train_matrix.shape)
    print("Validation shape:", validation_matrix.shape)
    print("Test shape      :", test_matrix.shape)

    print()
    print("Non-zero values:")
    print("Train       :", train_matrix.nnz)
    print("Validation  :", validation_matrix.nnz)
    print("Test        :", test_matrix.nnz)

    print()
    print("Density:")
    print(
        "Train       :",
        f"{train_matrix.nnz / (train_matrix.shape[0] * train_matrix.shape[1]):.6%}"
    )
    print(
        "Validation  :",
        f"{validation_matrix.nnz / (validation_matrix.shape[0] * validation_matrix.shape[1]):.6%}"
    )
    print(
        "Test        :",
        f"{test_matrix.nnz / (test_matrix.shape[0] * test_matrix.shape[1]):.6%}"
    )

    vectorizer_path = TFIDF_DIR / f"{feature_name}_vectorizer.joblib"

    joblib.dump(
        vectorizer,
        vectorizer_path,
    )

    save_matrix(
        train_matrix,
        FEATURE_DIR / feature_name.replace("imported_", "").replace("_names", "") / "train.npz",
    )

    save_matrix(
        validation_matrix,
        FEATURE_DIR / feature_name.replace("imported_", "").replace("_names", "") / "validation.npz",
    )

    save_matrix(
        test_matrix,
        FEATURE_DIR / feature_name.replace("imported_", "").replace("_names", "") / "test.npz",
    )

    feature_names = vectorizer.get_feature_names_out()

    feature_names_path = (
        FEATURE_DIR
        / feature_name.replace("imported_", "").replace("_names", "")
        / "feature_names.txt"
    )

    with open(
        feature_names_path,
        "w",
        encoding="utf-8",
    ) as f:
        for token in feature_names:
            f.write(token + "\n")

    return {
        "vocabulary_size": vocabulary_size,
        "train_shape": list(train_matrix.shape),
        "validation_shape": list(validation_matrix.shape),
        "test_shape": list(test_matrix.shape),
        "train_nnz": int(train_matrix.nnz),
        "validation_nnz": int(validation_matrix.nnz),
        "test_nnz": int(test_matrix.nnz),
        "vectorizer": str(vectorizer_path),
    }


def main():

    print("=" * 70)
    print("TF-IDF FEATURE ENGINEERING")
    print("=" * 70)

    FEATURE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    TFIDF_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    DLL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    API_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    train_df = load_split("train")
    validation_df = load_split("validation")
    test_df = load_split("test")

    print()
    print("Dataset sizes:")
    print("Train      :", len(train_df))
    print("Validation :", len(validation_df))
    print("Test       :", len(test_df))

    print()
    print("SHA verification:")
    print(
        "Train unique SHA      :",
        train_df["sha256"].nunique(),
    )
    print(
        "Validation unique SHA :",
        validation_df["sha256"].nunique(),
    )
    print(
        "Test unique SHA       :",
        test_df["sha256"].nunique(),
    )

    results = {}

    results["imported_dll_names"] = process_feature(
        "imported_dll_names",
        train_df,
        validation_df,
        test_df,
    )

    results["imported_api_names"] = process_feature(
        "imported_api_names",
        train_df,
        validation_df,
        test_df,
    )

    manifest = {
        "random_state": RANDOM_STATE,
        "vectorizer_parameters": {
            "ngram_range": [1, 1],
            "min_df": 1,
            "max_df": 1.0,
            "sublinear_tf": True,
            "norm": "l2",
            "lowercase": False,
            "token_separator": "|",
            "dtype": "float32",
        },
        "fitting_policy": (
            "TF-IDF vectorizers are fitted exclusively on the training split. "
            "Validation and test splits are transformed using the fitted "
            "training vectorizers."
        ),
        "representations": results,
    }

    manifest_path = FEATURE_DIR / "feature_manifest.json"

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
    print("=" * 70)
    print("TF-IDF FEATURE ENGINEERING COMPLETE")
    print("=" * 70)

    print()
    print("Manifest:")
    print(manifest_path)


if __name__ == "__main__":
    main()
