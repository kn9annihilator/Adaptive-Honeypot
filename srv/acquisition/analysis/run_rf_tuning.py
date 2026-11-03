from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
from scipy import sparse

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_recall_fscore_support


BASE_DIR = Path("/srv/acquisition/analysis")
DATASET_DIR = BASE_DIR / "dataset"
FEATURE_DIR = BASE_DIR / "features"
RESULT_DIR = BASE_DIR / "results" / "tuning" / "random_forest"

RANDOM_STATE = 42

REPRESENTATIONS = {
    "pe": FEATURE_DIR / "pe",
    "pe_dll": FEATURE_DIR / "combined" / "pe_dll",
}

# Controlled search around the baseline configuration.
CONFIGURATIONS = [
    {
        "n_estimators": 200,
        "max_depth": None,
        "min_samples_split": 2,
        "max_features": "sqrt",
    },
    {
        "n_estimators": 300,
        "max_depth": None,
        "min_samples_split": 2,
        "max_features": "sqrt",
    },
    {
        "n_estimators": 500,
        "max_depth": None,
        "min_samples_split": 2,
        "max_features": "sqrt",
    },
    {
        "n_estimators": 300,
        "max_depth": 10,
        "min_samples_split": 2,
        "max_features": "sqrt",
    },
    {
        "n_estimators": 300,
        "max_depth": 20,
        "min_samples_split": 2,
        "max_features": "sqrt",
    },
    {
        "n_estimators": 300,
        "max_depth": None,
        "min_samples_split": 5,
        "max_features": "sqrt",
    },
    {
        "n_estimators": 300,
        "max_depth": None,
        "min_samples_split": 2,
        "max_features": "log2",
    },
    {
        "n_estimators": 500,
        "max_depth": 20,
        "min_samples_split": 2,
        "max_features": "sqrt",
    },
]


def load_labels():
    train_df = pd.read_csv(DATASET_DIR / "train.csv")
    validation_df = pd.read_csv(DATASET_DIR / "validation.csv")

    return (
        train_df["family"].to_numpy(),
        validation_df["family"].to_numpy(),
    )


def evaluate_configuration(
    representation,
    X_train,
    X_validation,
    y_train,
    y_validation,
    config,
):
    model = RandomForestClassifier(
        **config,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight=None,
    )

    start = time.perf_counter()
    model.fit(X_train, y_train)
    fit_time = time.perf_counter() - start

    start = time.perf_counter()
    predictions = model.predict(X_validation)
    prediction_time = time.perf_counter() - start

    accuracy = accuracy_score(y_validation, predictions)

    macro_precision, macro_recall, macro_f1, _ = (
        precision_recall_fscore_support(
            y_validation,
            predictions,
            average="macro",
            zero_division=0,
        )
    )

    _, _, weighted_f1, _ = precision_recall_fscore_support(
        y_validation,
        predictions,
        average="weighted",
        zero_division=0,
    )

    return {
        "representation": representation,
        "model": "random_forest",
        **config,
        "random_state": RANDOM_STATE,
        "accuracy": float(accuracy),
        "macro_precision": float(macro_precision),
        "macro_recall": float(macro_recall),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "fit_time_seconds": float(fit_time),
        "prediction_time_seconds": float(prediction_time),
    }, model


def main():
    print("=" * 78)
    print("RANDOM FOREST CONTROLLED HYPERPARAMETER TUNING")
    print("TRAIN -> VALIDATION ONLY")
    print("=" * 78)

    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    y_train, y_validation = load_labels()

    results = []

    for representation, directory in REPRESENTATIONS.items():

        print()
        print("=" * 78)
        print("REPRESENTATION:", representation.upper())
        print("=" * 78)

        X_train = sparse.load_npz(directory / "train.npz")
        X_validation = sparse.load_npz(directory / "validation.npz")

        print("Train shape      :", X_train.shape)
        print("Validation shape :", X_validation.shape)
        print("Configurations   :", len(CONFIGURATIONS))

        for index, config in enumerate(CONFIGURATIONS, start=1):

            print()
            print(f"Configuration {index}/{len(CONFIGURATIONS)}")
            print(config)

            row, model = evaluate_configuration(
                representation,
                X_train,
                X_validation,
                y_train,
                y_validation,
                config,
            )

            results.append(row)

            print(f"Accuracy       : {row['accuracy']:.4f}")
            print(f"Macro Precision: {row['macro_precision']:.4f}")
            print(f"Macro Recall   : {row['macro_recall']:.4f}")
            print(f"Macro F1       : {row['macro_f1']:.4f}")
            print(f"Weighted F1    : {row['weighted_f1']:.4f}")
            print(f"Fit time       : {row['fit_time_seconds']:.3f}s")

    results_df = pd.DataFrame(results)
    results_df = results_df.sort_values(
        by="macro_f1",
        ascending=False,
    )

    results_path = RESULT_DIR / "rf_tuning_results.csv"
    results_df.to_csv(results_path, index=False)

    config_path = RESULT_DIR / "rf_tuning_config.json"

    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "protocol": "train -> validation",
                "test_set_used": False,
                "random_state": RANDOM_STATE,
                "primary_selection_metric": "macro_f1",
                "representations": list(REPRESENTATIONS.keys()),
                "configurations": CONFIGURATIONS,
            },
            f,
            indent=2,
        )

    print()
    print("=" * 78)
    print("RANDOM FOREST TUNING RESULTS")
    print("=" * 78)

    print(
        results_df[
            [
                "representation",
                "n_estimators",
                "max_depth",
                "min_samples_split",
                "max_features",
                "accuracy",
                "macro_f1",
                "weighted_f1",
                "fit_time_seconds",
            ]
        ].to_string(index=False)
    )

    print()
    print("Results saved:")
    print(results_path)

    print()
    print("Configuration saved:")
    print(config_path)

    print()
    print("=" * 78)
    print("RANDOM FOREST TUNING COMPLETE")
    print("=" * 78)


if __name__ == "__main__":
    main()
