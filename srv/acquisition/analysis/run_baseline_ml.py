#!/usr/bin/env python3

from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
from scipy import sparse

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier


BASE_DIR = Path("/srv/acquisition/analysis")
DATASET_DIR = BASE_DIR / "dataset"
FEATURE_DIR = BASE_DIR / "features"
RESULT_DIR = BASE_DIR / "results" / "baseline_ml"

RANDOM_STATE = 42

REPRESENTATIONS = {
    "pe": FEATURE_DIR / "pe",
    "dll": FEATURE_DIR / "dll",
    "api": FEATURE_DIR / "api",
    "pe_dll": FEATURE_DIR / "combined" / "pe_dll",
    "pe_api": FEATURE_DIR / "combined" / "pe_api",
    "pe_dll_api": FEATURE_DIR / "combined" / "pe_dll_api",
}


def load_labels():

    train_df = pd.read_csv(
        DATASET_DIR / "train.csv"
    )

    validation_df = pd.read_csv(
        DATASET_DIR / "validation.csv"
    )

    return (
        train_df["family"].to_numpy(),
        validation_df["family"].to_numpy(),
    )


def load_representation(name):

    directory = REPRESENTATIONS[name]

    X_train = sparse.load_npz(
        directory / "train.npz"
    )

    X_validation = sparse.load_npz(
        directory / "validation.npz"
    )

    return X_train, X_validation


def build_models():

    return {
       "svm": LinearSVC(
   		 C=1.0,
    		max_iter=100000,
    		random_state=RANDOM_STATE,
          ),

        "random_forest": RandomForestClassifier(
            n_estimators=300,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight=None,
        ),

        "xgboost": XGBClassifier(
            objective="multi:softprob",
            num_class=12,
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=1.0,
            colsample_bytree=1.0,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            eval_metric="mlogloss",
        ),
    }


def evaluate(
    model,
    X_train,
    y_train,
    X_validation,
    y_validation,
):

    start = time.perf_counter()

    model.fit(
        X_train,
        y_train,
    )

    fit_time = (
        time.perf_counter() - start
    )

    start = time.perf_counter()

    predictions = model.predict(
        X_validation
    )

    prediction_time = (
        time.perf_counter() - start
    )

    accuracy = accuracy_score(
        y_validation,
        predictions,
    )

    macro_precision, macro_recall, macro_f1, _ = (
        precision_recall_fscore_support(
            y_validation,
            predictions,
            average="macro",
            zero_division=0,
        )
    )

    _, _, weighted_f1, _ = (
        precision_recall_fscore_support(
            y_validation,
            predictions,
            average="weighted",
            zero_division=0,
        )
    )

    return {
        "accuracy": float(accuracy),
        "macro_precision": float(macro_precision),
        "macro_recall": float(macro_recall),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "fit_time_seconds": float(fit_time),
        "prediction_time_seconds": float(
            prediction_time
        ),
        "predictions": predictions,
    }


def main():

    print("=" * 78)
    print("BASELINE MALWARE FAMILY CLASSIFICATION")
    print("TRAIN -> VALIDATION ONLY")
    print("=" * 78)

    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    y_train, y_validation = load_labels()

    classes = sorted(
        set(y_train)
        | set(y_validation)
    )

    if len(classes) != 12:
        raise ValueError(
            f"Expected 12 classes, found {len(classes)}"
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

    print()
    print("Training samples   :", len(y_train))
    print("Validation samples :", len(y_validation))
    print("Classes            :", len(classes))
    print("Class mapping:")

    for family, class_id in class_to_id.items():
        print(
            f"  {class_id:2d} -> {family}"
        )

    results = []

    for representation in REPRESENTATIONS:

        print()
        print("=" * 78)
        print(
            "REPRESENTATION:",
            representation.upper()
        )
        print("=" * 78)

        X_train, X_validation = (
            load_representation(
                representation
            )
        )

        if X_train.shape[0] != len(y_train):
            raise ValueError(
                f"Training row mismatch: "
                f"{representation}"
            )

        if X_validation.shape[0] != len(y_validation):
            raise ValueError(
                f"Validation row mismatch: "
                f"{representation}"
            )

        print(
            "Train shape      :",
            X_train.shape
        )

        print(
            "Validation shape :",
            X_validation.shape
        )

        models = build_models()

        for model_name, model in models.items():

            print()
            print(
                f"Training {model_name}..."
            )

            evaluation = evaluate(
                model,
                X_train,
                y_train_encoded
                if model_name == "xgboost"
                else y_train,
                X_validation,
                y_validation_encoded
                if model_name == "xgboost"
                else y_validation,
            )

            predictions_encoded = evaluation.pop(
                "predictions"
            )

            if model_name == "xgboost":
                predictions = np.array(
                    [
                        classes[int(x)]
                        for x in predictions_encoded
                    ]
                )
            else:
                predictions = predictions_encoded

            experiment_name = (
                f"{representation}__{model_name}"
            )

            experiment_dir = (
                RESULT_DIR / experiment_name
            )

            experiment_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            joblib.dump(
                model,
                experiment_dir / "model.joblib",
            )

            report = classification_report(
                y_validation,
                predictions,
                labels=classes,
                output_dict=True,
                zero_division=0,
            )

            with open(
                experiment_dir
                / "classification_report.json",
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(
                    report,
                    f,
                    indent=2,
                )

            cm = confusion_matrix(
                y_validation,
                predictions,
                labels=classes,
            )

            pd.DataFrame(
                cm,
                index=classes,
                columns=classes,
            ).to_csv(
                experiment_dir
                / "confusion_matrix.csv"
            )

            predictions_df = pd.DataFrame(
                {
                    "actual": y_validation,
                    "predicted": predictions,
                }
            )

            predictions_df.to_csv(
                experiment_dir
                / "validation_predictions.csv",
                index=False,
            )

            row = {
                "representation": representation,
                "model": model_name,
                **evaluation,
            }

            results.append(row)

            print(
                f"Accuracy       : "
                f"{evaluation['accuracy']:.4f}"
            )

            print(
                f"Macro Precision: "
                f"{evaluation['macro_precision']:.4f}"
            )

            print(
                f"Macro Recall   : "
                f"{evaluation['macro_recall']:.4f}"
            )

            print(
                f"Macro F1       : "
                f"{evaluation['macro_f1']:.4f}"
            )

            print(
                f"Weighted F1    : "
                f"{evaluation['weighted_f1']:.4f}"
            )

            print(
                f"Fit time       : "
                f"{evaluation['fit_time_seconds']:.3f}s"
            )

    results_df = pd.DataFrame(
        results
    )

    results_df = results_df.sort_values(
        by="macro_f1",
        ascending=False,
    )

    results_path = (
        RESULT_DIR
        / "validation_results.csv"
    )

    results_df.to_csv(
        results_path,
        index=False,
    )

    experiment_config = {
        "random_state": RANDOM_STATE,
        "protocol": "train -> validation",
        "test_set_used": False,
        "models": {
            "svm": {
   	       "type": "LinearSVC",
    		"C": 1.0,
	        "max_iter": 10000,
            },
            "random_forest": {
                "type": "RandomForestClassifier",
                "n_estimators": 300,
                "class_weight": None,
            },
            "xgboost": {
                "type": "XGBClassifier",
                "objective": "multi:softprob",
                "num_class": 12,
                "n_estimators": 300,
                "max_depth": 6,
                "learning_rate": 0.1,
                "subsample": 1.0,
                "colsample_bytree": 1.0,
                "eval_metric": "mlogloss",
            },
        },
        "representations": list(
            REPRESENTATIONS.keys()
        ),
    }

    with open(
        RESULT_DIR / "experiment_config.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            experiment_config,
            f,
            indent=2,
        )

    print()
    print("=" * 78)
    print("VALIDATION RESULTS")
    print("=" * 78)

    print(
        results_df[
            [
                "representation",
                "model",
                "accuracy",
                "macro_precision",
                "macro_recall",
                "macro_f1",
                "weighted_f1",
            ]
        ].to_string(
            index=False
        )
    )

    print()
    print("Results saved:")
    print(results_path)

    print()
    print("=" * 78)
    print("BASELINE VALIDATION COMPLETE")
    print("=" * 78)


if __name__ == "__main__":
    main()
