from pathlib import Path
import json
import time

import numpy as np
import pandas as pd
from scipy import sparse
from xgboost import XGBClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
)


BASE_DIR = Path("/srv/acquisition/analysis")
DATASET_DIR = BASE_DIR / "dataset"
FEATURE_DIR = BASE_DIR / "features"
RESULT_DIR = BASE_DIR / "results" / "tuning" / "xgboost"

RANDOM_STATE = 42
NUM_CLASSES = 12

REPRESENTATIONS = {
    "pe": FEATURE_DIR / "pe",
    "pe_dll": FEATURE_DIR / "combined" / "pe_dll",
}

# Controlled search around the original baseline:
#
# baseline:
#   n_estimators=300
#   max_depth=6
#   learning_rate=0.1
#   subsample=1.0
#   colsample_bytree=1.0
#
# We vary tree complexity, learning rate, and sampling
# without creating a large Cartesian grid.

CONFIGURATIONS = [
    {
        "n_estimators": 200,
        "max_depth": 3,
        "learning_rate": 0.1,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
    {
        "n_estimators": 300,
        "max_depth": 3,
        "learning_rate": 0.1,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
    {
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.1,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
    {
        "n_estimators": 500,
        "max_depth": 6,
        "learning_rate": 0.1,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
    {
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
    {
        "n_estimators": 500,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
    {
        "n_estimators": 300,
        "max_depth": 3,
        "learning_rate": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
    },
    {
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
    },
    {
        "n_estimators": 500,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
    },
    {
        "n_estimators": 300,
        "max_depth": 9,
        "learning_rate": 0.1,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
    },
]


def load_labels():
    train_df = pd.read_csv(DATASET_DIR / "train.csv")
    validation_df = pd.read_csv(DATASET_DIR / "validation.csv")

    y_train = train_df["family"].to_numpy()
    y_validation = validation_df["family"].to_numpy()

    classes = sorted(set(y_train) | set(y_validation))

    if len(classes) != NUM_CLASSES:
        raise ValueError(
            f"Expected {NUM_CLASSES} classes, found {len(classes)}"
        )

    class_to_id = {
        family: idx
        for idx, family in enumerate(classes)
    }

    y_train_encoded = np.array(
        [class_to_id[x] for x in y_train],
        dtype=np.int32,
    )

    y_validation_encoded = np.array(
        [class_to_id[x] for x in y_validation],
        dtype=np.int32,
    )

    return (
        y_train,
        y_validation,
        y_train_encoded,
        y_validation_encoded,
        classes,
    )


def evaluate_configuration(
    representation,
    X_train,
    X_validation,
    y_train_encoded,
    y_validation_encoded,
    y_validation,
    config,
):
    model = XGBClassifier(
        objective="multi:softprob",
        num_class=NUM_CLASSES,
        eval_metric="mlogloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        **config,
    )

    start = time.perf_counter()
    model.fit(X_train, y_train_encoded)
    fit_time = time.perf_counter() - start

    start = time.perf_counter()
    predictions_encoded = model.predict(X_validation)
    prediction_time = time.perf_counter() - start

    predictions = np.asarray(
        predictions_encoded,
        dtype=np.int32,
    )

    accuracy = accuracy_score(
        y_validation_encoded,
        predictions,
    )

    macro_precision, macro_recall, macro_f1, _ = (
        precision_recall_fscore_support(
            y_validation_encoded,
            predictions,
            average="macro",
            zero_division=0,
        )
    )

    _, _, weighted_f1, _ = precision_recall_fscore_support(
        y_validation_encoded,
        predictions,
        average="weighted",
        zero_division=0,
    )

    return {
        "representation": representation,
        "model": "xgboost",
        **config,
        "random_state": RANDOM_STATE,
        "accuracy": float(accuracy),
        "macro_precision": float(macro_precision),
        "macro_recall": float(macro_recall),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "fit_time_seconds": float(fit_time),
        "prediction_time_seconds": float(prediction_time),
    }


def main():
    print("=" * 78)
    print("XGBOOST CONTROLLED HYPERPARAMETER TUNING")
    print("TRAIN -> VALIDATION ONLY")
    print("=" * 78)

    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    (
        y_train,
        y_validation,
        y_train_encoded,
        y_validation_encoded,
        classes,
    ) = load_labels()

    print()
    print("Training samples   :", len(y_train))
    print("Validation samples :", len(y_validation))
    print("Classes            :", len(classes))

    results = []

    for representation, directory in REPRESENTATIONS.items():

        print()
        print("=" * 78)
        print("REPRESENTATION:", representation.upper())
        print("=" * 78)

        X_train = sparse.load_npz(
            directory / "train.npz"
        )

        X_validation = sparse.load_npz(
            directory / "validation.npz"
        )

        print("Train shape      :", X_train.shape)
        print("Validation shape :", X_validation.shape)
        print("Configurations   :", len(CONFIGURATIONS))

        for index, config in enumerate(
            CONFIGURATIONS,
            start=1,
        ):

            print()
            print(
                f"Configuration "
                f"{index}/{len(CONFIGURATIONS)}"
            )
            print(config)

            row = evaluate_configuration(
                representation,
                X_train,
                X_validation,
                y_train_encoded,
                y_validation_encoded,
                y_validation,
                config,
            )

            results.append(row)

            print(
                f"Accuracy       : "
                f"{row['accuracy']:.4f}"
            )

            print(
                f"Macro Precision: "
                f"{row['macro_precision']:.4f}"
            )

            print(
                f"Macro Recall   : "
                f"{row['macro_recall']:.4f}"
            )

            print(
                f"Macro F1       : "
                f"{row['macro_f1']:.4f}"
            )

            print(
                f"Weighted F1    : "
                f"{row['weighted_f1']:.4f}"
            )

            print(
                f"Fit time       : "
                f"{row['fit_time_seconds']:.3f}s"
            )

    results_df = pd.DataFrame(results)

    results_df = results_df.sort_values(
        by="macro_f1",
        ascending=False,
    )

    results_path = (
        RESULT_DIR / "xgb_tuning_results.csv"
    )

    results_df.to_csv(
        results_path,
        index=False,
    )

    config_path = (
        RESULT_DIR / "xgb_tuning_config.json"
    )

    with open(
        config_path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            {
                "protocol": "train -> validation",
                "test_set_used": False,
                "random_state": RANDOM_STATE,
                "primary_selection_metric": "macro_f1",
                "representations": list(
                    REPRESENTATIONS.keys()
                ),
                "configurations": CONFIGURATIONS,
            },
            f,
            indent=2,
        )

    print()
    print("=" * 78)
    print("XGBOOST TUNING RESULTS")
    print("=" * 78)

    print(
        results_df[
            [
                "representation",
                "n_estimators",
                "max_depth",
                "learning_rate",
                "subsample",
                "colsample_bytree",
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
    print("XGBOOST TUNING COMPLETE")
    print("=" * 78)


if __name__ == "__main__":
    main()
