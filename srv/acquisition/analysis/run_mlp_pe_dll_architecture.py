#!/usr/bin/env python3

"""
Controlled MLP Architecture / Regularization Experiment
=========================================================

Purpose
-------
Evaluate three controlled MLP variants on the frozen PE+DLL
100-dimensional static malware representation.

Existing Variant A is already completed and is used only as
the reference:

    A: 100 -> 128 -> 64 -> 32 -> 12
       Dropout = 0.30

This script evaluates:

    B: 100 -> 128 -> 64 -> 12
       Dropout = 0.30

    C: 100 -> 128 -> 64 -> 32 -> 12
       Dropout = 0.20

    D: 100 -> 128 -> 64 -> 32 -> 12
       Dropout = 0.10


Controlled variables
--------------------
Representation:
    PE + DLL

Input dimension:
    100

Training split:
    1132 samples

Validation split:
    243 samples

Test set:
    NOT LOADED

Random seed:
    42

Optimizer:
    Adam

Learning rate:
    0.001

Batch size:
    32

Maximum epochs:
    100

Early stopping:
    Validation Macro-F1

Patience:
    15

Loss:
    CrossEntropyLoss

Classes:
    12

Device:
    CPU unless CUDA is available


IMPORTANT
---------
The PE+DLL matrices are stored as SciPy CSR sparse NPZ files
using scipy.sparse.save_npz().

Therefore they MUST be loaded using scipy.sparse.load_npz().

The labels are loaded from the frozen train.csv and
validation.csv split files.

The test split is never loaded.

No malware sample is executed by this script.
"""


# ============================================================
# IMPORTS
# ============================================================

import csv
import json
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from scipy.sparse import load_npz

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from torch.utils.data import (
    DataLoader,
    TensorDataset,
)


# ============================================================
# 1. GLOBAL CONFIGURATION
# ============================================================

SEED = 42

LEARNING_RATE = 1e-3

BATCH_SIZE = 32

MAX_EPOCHS = 100

PATIENCE = 15

NUM_CLASSES = 12

EXPECTED_INPUT_DIM = 100

EXPECTED_TRAIN_SAMPLES = 1132

EXPECTED_VALIDATION_SAMPLES = 243


# ============================================================
# 2. PROJECT PATHS
# ============================================================

BASE_DIR = Path(
    "/srv/acquisition/analysis"
)


# ------------------------------------------------------------
# PE + DLL feature matrices
# ------------------------------------------------------------

FEATURE_DIR = (
    BASE_DIR
    / "features"
    / "combined"
    / "pe_dll"
)


TRAIN_FEATURE_FILE = (
    FEATURE_DIR
    / "train.npz"
)


VALIDATION_FEATURE_FILE = (
    FEATURE_DIR
    / "validation.npz"
)


# ------------------------------------------------------------
# Frozen split CSVs
# ------------------------------------------------------------

DATASET_DIR = (
    BASE_DIR
    / "dataset"
)


TRAIN_LABEL_FILE = (
    DATASET_DIR
    / "train.csv"
)


VALIDATION_LABEL_FILE = (
    DATASET_DIR
    / "validation.csv"
)


# ------------------------------------------------------------
# Results
# ------------------------------------------------------------

RESULT_DIR = (
    BASE_DIR
    / "results"
    / "deep_learning"
    / "static_mlp"
    / "architecture_experiments"
)


# ============================================================
# 3. EXPERIMENT VARIANTS
# ============================================================

VARIANTS = {

    "B": {
        "description":
            "100 -> 128 -> 64 -> 12, dropout=0.30",

        "hidden_layers":
            [128, 64],

        "dropout":
            0.30,
    },

    "C": {
        "description":
            "100 -> 128 -> 64 -> 32 -> 12, dropout=0.20",

        "hidden_layers":
            [128, 64, 32],

        "dropout":
            0.20,
    },

    "D": {
        "description":
            "100 -> 128 -> 64 -> 32 -> 12, dropout=0.10",

        "hidden_layers":
            [128, 64, 32],

        "dropout":
            0.10,
    },
}


# ============================================================
# 4. EXISTING VARIANT A REFERENCE
# ============================================================

"""
Variant A was already experimentally evaluated.

We do NOT retrain it.

These values are the previously established reference.
"""

VARIANT_A_REFERENCE = {

    "variant":
        "A",

    "description":
        "100 -> 128 -> 64 -> 32 -> 12, dropout=0.30",

    "parameter_count":
        23660,

    "best_epoch":
        85,

    "accuracy":
        0.744856,

    "macro_precision":
        0.739472,

    "macro_recall":
        0.730836,

    "macro_f1":
        0.727253,

    "weighted_f1":
        0.742411,
}


# ============================================================
# 5. REPRODUCIBILITY
# ============================================================

def set_seed(seed=SEED):
    """
    Set random seeds for reproducibility.
    """

    random.seed(seed)

    np.random.seed(seed)

    torch.manual_seed(seed)

    if torch.cuda.is_available():

        torch.cuda.manual_seed_all(seed)

    if hasattr(
        torch.backends,
        "cudnn",
    ):

        torch.backends.cudnn.deterministic = True

        torch.backends.cudnn.benchmark = False


# ============================================================
# 6. LOAD CSR FEATURE MATRIX
# ============================================================

def load_feature_matrix(path):
    """
    Load a PE+DLL feature matrix stored using:

        scipy.sparse.save_npz()

    The stored NPZ contains CSR components such as:

        indices
        indptr
        format
        shape
        data

    scipy.sparse.load_npz() reconstructs the original matrix.

    The matrix is converted to dense float32 because the MLP
    consumes a conventional dense tensor.
    """

    path = Path(path)

    if not path.exists():

        raise FileNotFoundError(
            f"Feature file does not exist:\n{path}"
        )

    print()
    print(
        f"Loading sparse feature matrix:\n{path}"
    )

    sparse_matrix = load_npz(path)

    print(
        f"  Sparse format : "
        f"{sparse_matrix.format}"
    )

    print(
        f"  Sparse shape  : "
        f"{sparse_matrix.shape}"
    )

    print(
        f"  Non-zero      : "
        f"{sparse_matrix.nnz}"
    )

    if sparse_matrix.format != "csr":

        raise ValueError(
            f"Expected CSR matrix but found "
            f"{sparse_matrix.format} in {path}"
        )

    dense_matrix = sparse_matrix.toarray()

    dense_matrix = dense_matrix.astype(
        np.float32,
        copy=False,
    )

    return dense_matrix


# ============================================================
# 7. FIND CSV COLUMN
# ============================================================

def find_column(fieldnames, candidates):
    """
    Find the first matching column from a list of possible
    column names.
    """

    normalized = {
        field.strip().lower(): field
        for field in fieldnames
    }

    for candidate in candidates:

        candidate_lower = candidate.lower()

        if candidate_lower in normalized:

            return normalized[
                candidate_lower
            ]

    return None


# ============================================================
# 8. LOAD LABELS FROM FROZEN SPLIT CSV
# ============================================================

def load_labels_from_csv(path):
    """
    Load family labels from an existing frozen split CSV.

    The loader searches for a 'family' column first.

    It also supports common alternatives if the exact CSV
    schema uses another label column.
    """

    path = Path(path)

    if not path.exists():

        raise FileNotFoundError(
            f"Label file does not exist:\n{path}"
        )

    with open(
        path,
        "r",
        newline="",
        encoding="utf-8",
    ) as file:

        reader = csv.DictReader(file)

        fieldnames = reader.fieldnames

        if fieldnames is None:

            raise ValueError(
                f"No CSV header found in {path}"
            )

        family_column = find_column(
            fieldnames,
            [
                "family",
                "label",
                "target",
            ],
        )

        if family_column is None:

            raise ValueError(
                f"Could not identify family/label "
                f"column in {path}.\n"
                f"Columns found: {fieldnames}"
            )

        labels = []

        for row in reader:

            value = row.get(
                family_column
            )

            if value is None:

                raise ValueError(
                    f"Missing label in {path}"
                )

            value = value.strip()

            if value == "":

                raise ValueError(
                    f"Empty label in {path}"
                )

            labels.append(value)

    return labels


# ============================================================
# 9. CONVERT FAMILY LABELS TO NUMERIC CLASS IDS
# ============================================================

def create_label_mapping(
    train_labels,
    validation_labels,
):
    """
    Create one frozen family -> integer mapping for the
    complete experiment.

    Mapping is created from the union of the labels and sorted
    deterministically.

    Expected result: 12 classes.
    """

    families = sorted(
        set(train_labels)
        | set(validation_labels)
    )

    if len(families) != NUM_CLASSES:

        raise ValueError(
            f"Expected {NUM_CLASSES} families, "
            f"found {len(families)}:\n"
            f"{families}"
        )

    label_to_id = {
        family: index
        for index, family
        in enumerate(families)
    }

    id_to_label = {
        index: family
        for family, index
        in label_to_id.items()
    }

    return (
        label_to_id,
        id_to_label,
    )


# ============================================================
# 10. CONVERT LABELS
# ============================================================

def encode_labels(
    labels,
    label_to_id,
):
    """
    Convert family strings to integer class IDs.
    """

    encoded = []

    for label in labels:

        if label not in label_to_id:

            raise ValueError(
                f"Unknown family label: {label}"
            )

        encoded.append(
            label_to_id[label]
        )

    return np.asarray(
        encoded,
        dtype=np.int64,
    )


# ============================================================
# 11. LOAD TRAIN / VALIDATION DATA
# ============================================================

def load_train_validation_data():
    """
    Load:

        train feature matrix
        validation feature matrix
        train labels
        validation labels

    The test set is intentionally never loaded.
    """

    print()
    print("=" * 72)
    print("DATA LOADING")
    print("=" * 72)

    print(
        f"Train features      : "
        f"{TRAIN_FEATURE_FILE}"
    )

    print(
        f"Validation features : "
        f"{VALIDATION_FEATURE_FILE}"
    )

    print(
        f"Train labels        : "
        f"{TRAIN_LABEL_FILE}"
    )

    print(
        f"Validation labels   : "
        f"{VALIDATION_LABEL_FILE}"
    )

    # --------------------------------------------------------
    # Load feature matrices
    # --------------------------------------------------------

    X_train = load_feature_matrix(
        TRAIN_FEATURE_FILE
    )

    X_val = load_feature_matrix(
        VALIDATION_FEATURE_FILE
    )

    # --------------------------------------------------------
    # Load labels
    # --------------------------------------------------------

    train_labels = load_labels_from_csv(
        TRAIN_LABEL_FILE
    )

    validation_labels = load_labels_from_csv(
        VALIDATION_LABEL_FILE
    )

    # --------------------------------------------------------
    # Basic dimensions
    # --------------------------------------------------------

    print()
    print(
        f"Training feature shape     : "
        f"{X_train.shape}"
    )

    print(
        f"Validation feature shape   : "
        f"{X_val.shape}"
    )

    print(
        f"Training label count       : "
        f"{len(train_labels)}"
    )

    print(
        f"Validation label count     : "
        f"{len(validation_labels)}"
    )

    # --------------------------------------------------------
    # Structural checks
    # --------------------------------------------------------

    if X_train.ndim != 2:

        raise ValueError(
            f"Training matrix must be 2-dimensional. "
            f"Got shape {X_train.shape}"
        )

    if X_val.ndim != 2:

        raise ValueError(
            f"Validation matrix must be 2-dimensional. "
            f"Got shape {X_val.shape}"
        )

    if X_train.shape[1] != EXPECTED_INPUT_DIM:

        raise ValueError(
            f"Expected {EXPECTED_INPUT_DIM} PE+DLL "
            f"features but found "
            f"{X_train.shape[1]}"
        )

    if X_val.shape[1] != EXPECTED_INPUT_DIM:

        raise ValueError(
            f"Expected {EXPECTED_INPUT_DIM} PE+DLL "
            f"features but found "
            f"{X_val.shape[1]}"
        )

    if X_train.shape[0] != EXPECTED_TRAIN_SAMPLES:

        raise ValueError(
            f"Expected "
            f"{EXPECTED_TRAIN_SAMPLES} training samples "
            f"but found "
            f"{X_train.shape[0]}"
        )

    if X_val.shape[0] != EXPECTED_VALIDATION_SAMPLES:

        raise ValueError(
            f"Expected "
            f"{EXPECTED_VALIDATION_SAMPLES} validation samples "
            f"but found "
            f"{X_val.shape[0]}"
        )

    if len(train_labels) != X_train.shape[0]:

        raise ValueError(
            "Training feature/label count mismatch:\n"
            f"Features: {X_train.shape[0]}\n"
            f"Labels:   {len(train_labels)}"
        )

    if len(validation_labels) != X_val.shape[0]:

        raise ValueError(
            "Validation feature/label count mismatch:\n"
            f"Features: {X_val.shape[0]}\n"
            f"Labels:   {len(validation_labels)}"
        )

    # --------------------------------------------------------
    # Numeric checks
    # --------------------------------------------------------

    if not np.isfinite(X_train).all():

        raise ValueError(
            "Training matrix contains NaN "
            "or infinite values."
        )

    if not np.isfinite(X_val).all():

        raise ValueError(
            "Validation matrix contains NaN "
            "or infinite values."
        )

    # --------------------------------------------------------
    # Label mapping
    # --------------------------------------------------------

    (
        label_to_id,
        id_to_label,
    ) = create_label_mapping(
        train_labels,
        validation_labels,
    )

    y_train = encode_labels(
        train_labels,
        label_to_id,
    )

    y_val = encode_labels(
        validation_labels,
        label_to_id,
    )

    print()
    print("Frozen family -> class mapping:")

    for class_id in range(NUM_CLASSES):

        print(
            f"  {class_id:2d} -> "
            f"{id_to_label[class_id]}"
        )

    # --------------------------------------------------------
    # Label coverage
    # --------------------------------------------------------

    train_classes = sorted(
        np.unique(y_train).tolist()
    )

    val_classes = sorted(
        np.unique(y_val).tolist()
    )

    expected_classes = list(
        range(NUM_CLASSES)
    )

    print()
    print(
        f"Training class IDs   : "
        f"{train_classes}"
    )

    print(
        f"Validation class IDs : "
        f"{val_classes}"
    )

    if train_classes != expected_classes:

        raise ValueError(
            "Training split does not contain "
            "all expected classes."
        )

    if val_classes != expected_classes:

        raise ValueError(
            "Validation split does not contain "
            "all expected classes."
        )

    # --------------------------------------------------------
    # Final validation message
    # --------------------------------------------------------

    print()
    print("Data validation: PASS")

    return (
        X_train,
        y_train,
        X_val,
        y_val,
        label_to_id,
        id_to_label,
    )


# ============================================================
# 12. MODEL
# ============================================================

class MLP(nn.Module):
    """
    Fully connected multilayer perceptron.

    Example:

        100 -> 128 -> 64 -> 32 -> 12
    """

    def __init__(
        self,
        input_dim,
        hidden_layers,
        dropout,
        num_classes,
    ):
        super().__init__()

        layers = []

        previous_dim = input_dim

        for hidden_dim in hidden_layers:

            layers.append(
                nn.Linear(
                    previous_dim,
                    hidden_dim,
                )
            )

            layers.append(
                nn.ReLU()
            )

            layers.append(
                nn.Dropout(
                    dropout
                )
            )

            previous_dim = hidden_dim

        # Final logits layer.
        #
        # Softmax is intentionally NOT applied here.
        # CrossEntropyLoss handles the required operation.
        layers.append(
            nn.Linear(
                previous_dim,
                num_classes,
            )
        )

        self.network = nn.Sequential(
            *layers
        )

    def forward(self, x):

        return self.network(x)


# ============================================================
# 13. PARAMETER COUNT
# ============================================================

def count_trainable_parameters(model):

    return sum(
        parameter.numel()
        for parameter
        in model.parameters()
        if parameter.requires_grad
    )


# ============================================================
# 14. DATALOADERS
# ============================================================

def create_dataloaders(
    X_train,
    y_train,
    X_val,
    y_val,
):

    train_dataset = TensorDataset(
        torch.from_numpy(X_train),
        torch.from_numpy(y_train),
    )

    validation_dataset = TensorDataset(
        torch.from_numpy(X_val),
        torch.from_numpy(y_val),
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        shuffle=True,
        num_workers=0,
    )

    validation_loader = DataLoader(
        validation_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False,
        num_workers=0,
    )

    return (
        train_loader,
        validation_loader,
    )


# ============================================================
# 15. MODEL EVALUATION
# ============================================================

def evaluate_model(
    model,
    loader,
    device,
):
    """
    Evaluate a model and return metrics, labels,
    and predictions.
    """

    model.eval()

    criterion = nn.CrossEntropyLoss()

    all_true = []

    all_predictions = []

    total_loss = 0.0

    total_samples = 0

    with torch.no_grad():

        for X, y in loader:

            X = X.to(device)

            y = y.to(device)

            logits = model(X)

            loss = criterion(
                logits,
                y,
            )

            predictions = torch.argmax(
                logits,
                dim=1,
            )

            batch_size = y.size(0)

            total_loss += (
                loss.item()
                * batch_size
            )

            total_samples += batch_size

            all_true.extend(
                y.cpu().numpy()
            )

            all_predictions.extend(
                predictions.cpu().numpy()
            )

    y_true = np.asarray(
        all_true,
        dtype=np.int64,
    )

    y_pred = np.asarray(
        all_predictions,
        dtype=np.int64,
    )

    metrics = {

        "loss":
            total_loss / total_samples,

        "accuracy":
            accuracy_score(
                y_true,
                y_pred,
            ),

        "macro_precision":
            precision_score(
                y_true,
                y_pred,
                average="macro",
                zero_division=0,
            ),

        "macro_recall":
            recall_score(
                y_true,
                y_pred,
                average="macro",
                zero_division=0,
            ),

        "macro_f1":
            f1_score(
                y_true,
                y_pred,
                average="macro",
                zero_division=0,
            ),

        "weighted_f1":
            f1_score(
                y_true,
                y_pred,
                average="weighted",
                zero_division=0,
            ),
    }

    return (
        metrics,
        y_true,
        y_pred,
    )


# ============================================================
# 16. TRAIN ONE VARIANT
# ============================================================

def train_variant(
    variant_name,
    variant_config,
    X_train,
    y_train,
    X_val,
    y_val,
    device,
    id_to_label,
):

    # --------------------------------------------------------
    # Reset seed before every variant
    # --------------------------------------------------------

    set_seed(SEED)

    # --------------------------------------------------------
    # Output directory
    # --------------------------------------------------------

    output_dir = (
        RESULT_DIR
        / f"variant_{variant_name}"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # DataLoaders
    # --------------------------------------------------------

    (
        train_loader,
        validation_loader,
    ) = create_dataloaders(
        X_train,
        y_train,
        X_val,
        y_val,
    )

    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    model = MLP(
        input_dim=X_train.shape[1],

        hidden_layers=
            variant_config[
                "hidden_layers"
            ],

        dropout=
            variant_config[
                "dropout"
            ],

        num_classes=
            NUM_CLASSES,
    )

    model = model.to(device)

    parameter_count = (
        count_trainable_parameters(
            model
        )
    )

    # --------------------------------------------------------
    # Loss and optimizer
    # --------------------------------------------------------

    criterion = nn.CrossEntropyLoss()

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE,
    )

    # --------------------------------------------------------
    # Early stopping state
    # --------------------------------------------------------

    best_macro_f1 = -1.0

    best_epoch = 0

    patience_counter = 0

    best_state = None

    history = []

    # --------------------------------------------------------
    # Experiment header
    # --------------------------------------------------------

    print()
    print("=" * 72)
    print(
        f"VARIANT {variant_name}"
    )
    print("=" * 72)

    print(
        f"Architecture    : "
        f"{variant_config['description']}"
    )

    print(
        f"Input dimension  : "
        f"{X_train.shape[1]}"
    )

    print(
        f"Parameters       : "
        f"{parameter_count:,}"
    )

    print(
        f"Dropout          : "
        f"{variant_config['dropout']}"
    )

    print(
        f"Learning rate    : "
        f"{LEARNING_RATE}"
    )

    print(
        f"Batch size       : "
        f"{BATCH_SIZE}"
    )

    print(
        f"Max epochs       : "
        f"{MAX_EPOCHS}"
    )

    print(
        f"Early stopping   : "
        f"Validation Macro-F1, "
        f"patience={PATIENCE}"
    )

    print("-" * 72)

    # ========================================================
    # EPOCH LOOP
    # ========================================================

    for epoch in range(
        1,
        MAX_EPOCHS + 1,
    ):

        # ----------------------------------------------------
        # Training
        # ----------------------------------------------------

        model.train()

        running_loss = 0.0

        training_samples = 0

        for X, y in train_loader:

            X = X.to(device)

            y = y.to(device)

            optimizer.zero_grad()

            logits = model(X)

            loss = criterion(
                logits,
                y,
            )

            loss.backward()

            optimizer.step()

            batch_size = y.size(0)

            running_loss += (
                loss.item()
                * batch_size
            )

            training_samples += (
                batch_size
            )

        train_loss = (
            running_loss
            / training_samples
        )

        # ----------------------------------------------------
        # Training metrics
        # ----------------------------------------------------

        train_metrics, _, _ = (
            evaluate_model(
                model,
                train_loader,
                device,
            )
        )

        # ----------------------------------------------------
        # Validation metrics
        # ----------------------------------------------------

        validation_metrics, _, _ = (
            evaluate_model(
                model,
                validation_loader,
                device,
            )
        )

        # ----------------------------------------------------
        # Record history
        # ----------------------------------------------------

        epoch_record = {

            "epoch":
                epoch,

            "train_loss":
                train_loss,

            "train_accuracy":
                train_metrics[
                    "accuracy"
                ],

            "train_macro_precision":
                train_metrics[
                    "macro_precision"
                ],

            "train_macro_recall":
                train_metrics[
                    "macro_recall"
                ],

            "train_macro_f1":
                train_metrics[
                    "macro_f1"
                ],

            "train_weighted_f1":
                train_metrics[
                    "weighted_f1"
                ],

            "validation_loss":
                validation_metrics[
                    "loss"
                ],

            "validation_accuracy":
                validation_metrics[
                    "accuracy"
                ],

            "validation_macro_precision":
                validation_metrics[
                    "macro_precision"
                ],

            "validation_macro_recall":
                validation_metrics[
                    "macro_recall"
                ],

            "validation_macro_f1":
                validation_metrics[
                    "macro_f1"
                ],

            "validation_weighted_f1":
                validation_metrics[
                    "weighted_f1"
                ],
        }

        history.append(
            epoch_record
        )

        # ----------------------------------------------------
        # Console output
        # ----------------------------------------------------

        print(
            f"Epoch {epoch:03d} | "
            f"train_loss={train_loss:.4f} | "
            f"train_f1="
            f"{train_metrics['macro_f1']:.4f} | "
            f"val_loss="
            f"{validation_metrics['loss']:.4f} | "
            f"val_f1="
            f"{validation_metrics['macro_f1']:.4f}"
        )

        # ----------------------------------------------------
        # Early stopping
        # ----------------------------------------------------

        current_macro_f1 = (
            validation_metrics[
                "macro_f1"
            ]
        )

        if (
            current_macro_f1
            > best_macro_f1
        ):

            best_macro_f1 = (
                current_macro_f1
            )

            best_epoch = epoch

            patience_counter = 0

            best_state = {
                key:
                    value.detach()
                    .cpu()
                    .clone()

                for key, value
                in model.state_dict().items()
            }

        else:

            patience_counter += 1

        if (
            patience_counter
            >= PATIENCE
        ):

            print()

            print(
                f"Early stopping at "
                f"epoch {epoch}."
            )

            print(
                f"Best epoch: "
                f"{best_epoch}"
            )

            print(
                f"Best validation "
                f"Macro-F1: "
                f"{best_macro_f1:.6f}"
            )

            break

    # ========================================================
    # RESTORE BEST CHECKPOINT
    # ========================================================

    if best_state is None:

        raise RuntimeError(
            "No best model checkpoint "
            "was recorded."
        )

    model.load_state_dict(
        best_state
    )

    # ========================================================
    # FINAL VALIDATION EVALUATION
    # ========================================================

    (
        final_metrics,
        y_true,
        y_pred,
    ) = evaluate_model(
        model,
        validation_loader,
        device,
    )

    # ========================================================
    # SAVE MODEL
    # ========================================================

    checkpoint = {

        "model_state_dict":
            model.state_dict(),

        "input_dim":
            X_train.shape[1],

        "hidden_layers":
            variant_config[
                "hidden_layers"
            ],

        "dropout":
            variant_config[
                "dropout"
            ],

        "num_classes":
            NUM_CLASSES,

        "optimizer":
            "Adam",

        "learning_rate":
            LEARNING_RATE,

        "batch_size":
            BATCH_SIZE,

        "max_epochs":
            MAX_EPOCHS,

        "early_stopping_metric":
            "validation_macro_f1",

        "patience":
            PATIENCE,

        "seed":
            SEED,

        "best_epoch":
            best_epoch,

        "parameter_count":
            parameter_count,

        "test_set_used":
            False,
    }

    torch.save(
        checkpoint,
        output_dir
        / "model.pt",
    )

    # ========================================================
    # CLASSIFICATION REPORT
    # ========================================================

    target_names = [
        id_to_label[i]
        for i in range(NUM_CLASSES)
    ]

    report = classification_report(
        y_true,
        y_pred,
        labels=list(
            range(NUM_CLASSES)
        ),
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )

    with open(
        output_dir
        / "classification_report.json",
        "w",
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
        )

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    confusion = confusion_matrix(
        y_true,
        y_pred,
        labels=list(
            range(NUM_CLASSES)
        ),
    )

    # Save numeric matrix.
    np.savetxt(
        output_dir
        / "confusion_matrix.csv",
        confusion,
        delimiter=",",
        fmt="%d",
    )

    # Also save a labeled confusion matrix.
    with open(
        output_dir
        / "confusion_matrix_labeled.csv",
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.writer(
            file
        )

        writer.writerow(
            [
                "true/predicted"
            ]
            + target_names
        )

        for index, row in enumerate(
            confusion
        ):

            writer.writerow(
                [
                    target_names[index]
                ]
                + row.tolist()
            )

    # ========================================================
    # VALIDATION PREDICTIONS
    # ========================================================

    with open(
        output_dir
        / "validation_predictions.csv",
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.writer(
            file
        )

        writer.writerow(
            [
                "true_label_id",
                "true_family",
                "predicted_label_id",
                "predicted_family",
            ]
        )

        for true_id, pred_id in zip(
            y_true,
            y_pred,
        ):

            writer.writerow(
                [
                    int(true_id),
                    id_to_label[
                        int(true_id)
                    ],
                    int(pred_id),
                    id_to_label[
                        int(pred_id)
                    ],
                ]
            )

    # ========================================================
    # TRAINING HISTORY
    # ========================================================

    with open(
        output_dir
        / "training_history.json",
        "w",
    ) as file:

        json.dump(
            history,
            file,
            indent=2,
        )

    # ========================================================
    # EXPERIMENT CONFIGURATION
    # ========================================================

    experiment_config = {

        "experiment_type":
            "controlled_mlp_architecture_regularization",

        "variant":
            variant_name,

        "description":
            variant_config[
                "description"
            ],

        "representation":
            "PE+DLL",

        "input_dimension":
            X_train.shape[1],

        "train_samples":
            X_train.shape[0],

        "validation_samples":
            X_val.shape[0],

        "hidden_layers":
            variant_config[
                "hidden_layers"
            ],

        "dropout":
            variant_config[
                "dropout"
            ],

        "output_classes":
            NUM_CLASSES,

        "optimizer":
            "Adam",

        "learning_rate":
            LEARNING_RATE,

        "batch_size":
            BATCH_SIZE,

        "maximum_epochs":
            MAX_EPOCHS,

        "early_stopping_metric":
            "validation_macro_f1",

        "early_stopping_patience":
            PATIENCE,

        "random_seed":
            SEED,

        "device":
            str(device),

        "trainable_parameters":
            parameter_count,

        "best_epoch":
            best_epoch,

        "test_set_used":
            False,

        "malware_execution":
            False,

        "feature_storage":
            "SciPy CSR sparse NPZ",

        "label_source":
            "frozen split CSV",
    }

    with open(
        output_dir
        / "experiment_config.json",
        "w",
    ) as file:

        json.dump(
            experiment_config,
            file,
            indent=2,
        )

    # ========================================================
    # FINAL METRICS
    # ========================================================

    result = {

        "variant":
            variant_name,

        "description":
            variant_config[
                "description"
            ],

        "parameter_count":
            parameter_count,

        "best_epoch":
            best_epoch,

        "accuracy":
            final_metrics[
                "accuracy"
            ],

        "macro_precision":
            final_metrics[
                "macro_precision"
            ],

        "macro_recall":
            final_metrics[
                "macro_recall"
            ],

        "macro_f1":
            final_metrics[
                "macro_f1"
            ],

        "weighted_f1":
            final_metrics[
                "weighted_f1"
            ],
    }

    with open(
        output_dir
        / "metrics.json",
        "w",
    ) as file:

        json.dump(
            result,
            file,
            indent=2,
        )

    return result


# ============================================================
# 17. SAVE AGGREGATED COMPARISON
# ============================================================

def save_comparison(results):

    all_results = [
        VARIANT_A_REFERENCE
    ] + results

    ranked_results = sorted(
        all_results,
        key=lambda item:
            item["macro_f1"],
        reverse=True,
    )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    with open(
        RESULT_DIR
        / "architecture_comparison.json",
        "w",
    ) as file:

        json.dump(
            ranked_results,
            file,
            indent=2,
        )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    with open(
        RESULT_DIR
        / "architecture_comparison.csv",
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.writer(
            file
        )

        writer.writerow(
            [
                "variant",
                "description",
                "parameter_count",
                "best_epoch",
                "accuracy",
                "macro_precision",
                "macro_recall",
                "macro_f1",
                "weighted_f1",
            ]
        )

        for result in ranked_results:

            writer.writerow(
                [
                    result["variant"],
                    result["description"],
                    result["parameter_count"],
                    result.get(
                        "best_epoch",
                        "reference",
                    ),
                    f"{result['accuracy']:.6f}",
                    f"{result['macro_precision']:.6f}",
                    f"{result['macro_recall']:.6f}",
                    f"{result['macro_f1']:.6f}",
                    f"{result['weighted_f1']:.6f}",
                ]
            )

    return ranked_results


# ============================================================
# 18. MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # Reproducibility
    # --------------------------------------------------------

    set_seed(
        SEED
    )

    # --------------------------------------------------------
    # Device
    # --------------------------------------------------------

    if torch.cuda.is_available():

        device = torch.device(
            "cuda"
        )

    else:

        device = torch.device(
            "cpu"
        )

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    print()
    print("=" * 72)
    print(
        "PE+DLL MLP ARCHITECTURE "
        "EXPERIMENT"
    )
    print("=" * 72)

    print(
        f"PyTorch version : "
        f"{torch.__version__}"
    )

    print(
        f"Device          : "
        f"{device}"
    )

    print(
        f"Random seed     : "
        f"{SEED}"
    )

    # --------------------------------------------------------
    # Safety / evaluation constraints
    # --------------------------------------------------------

    print()
    print(
        "Evaluation constraints:"
    )

    print(
        "  - PE+DLL static features only"
    )

    print(
        "  - Malware samples are NOT executed"
    )

    print(
        "  - Test set is NOT loaded"
    )

    print(
        "  - Train/validation only"
    )

    print(
        "  - Variant A is reference only"
    )

    print(
        "  - Variants B/C/D are trained"
    )

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    (
        X_train,
        y_train,
        X_val,
        y_val,
        label_to_id,
        id_to_label,
    ) = load_train_validation_data()

    # Prevent unused-variable ambiguity.
    _ = label_to_id

    # --------------------------------------------------------
    # Create results directory
    # --------------------------------------------------------

    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Train variants B/C/D
    # --------------------------------------------------------

    results = []

    for (
        variant_name,
        variant_config
    ) in VARIANTS.items():

        result = train_variant(

            variant_name,

            variant_config,

            X_train,

            y_train,

            X_val,

            y_val,

            device,

            id_to_label,
        )

        results.append(
            result
        )

    # --------------------------------------------------------
    # Save comparison
    # --------------------------------------------------------

    ranked_results = save_comparison(
        results
    )

    # --------------------------------------------------------
    # Final comparison table
    # --------------------------------------------------------

    print()
    print("=" * 90)
    print(
        "FINAL ARCHITECTURE COMPARISON"
    )
    print("=" * 90)

    print(
        f"{'Variant':<10}"
        f"{'Parameters':>14}"
        f"{'Best Epoch':>12}"
        f"{'Accuracy':>12}"
        f"{'Macro-F1':>12}"
        f"{'Weighted-F1':>14}"
    )

    print(
        "-" * 90
    )

    for result in ranked_results:

        best_epoch = result.get(
            "best_epoch",
            "reference",
        )

        print(
            f"{result['variant']:<10}"
            f"{result['parameter_count']:>14,}"
            f"{str(best_epoch):>12}"
            f"{result['accuracy']:>12.4f}"
            f"{result['macro_f1']:>12.4f}"
            f"{result['weighted_f1']:>14.4f}"
        )

    # --------------------------------------------------------
    # Compare against Variant A
    # --------------------------------------------------------

    best_experimental_variant = max(
        results,
        key=lambda item:
            item["macro_f1"],
    )

    reference_f1 = (
        VARIANT_A_REFERENCE[
            "macro_f1"
        ]
    )

    best_f1 = (
        best_experimental_variant[
            "macro_f1"
        ]
    )

    improvement = (
        best_f1
        - reference_f1
    )

    print()
    print("=" * 72)
    print(
        "REFERENCE COMPARISON"
    )
    print("=" * 72)

    print(
        f"Variant A Macro-F1 : "
        f"{reference_f1:.6f}"
    )

    print(
        f"Best B/C/D         : "
        f"Variant "
        f"{best_experimental_variant['variant']}"
    )

    print(
        f"Best Macro-F1      : "
        f"{best_f1:.6f}"
    )

    print(
        f"Difference         : "
        f"{improvement:+.6f}"
    )

    print(
        f"Difference (pp)    : "
        f"{improvement * 100:+.2f}"
    )

    # --------------------------------------------------------
    # Interpretation
    # --------------------------------------------------------

    if improvement > 0.01:

        conclusion = (
            "Material improvement "
            "over Variant A."
        )

    elif improvement > 0.002:

        conclusion = (
            "Small improvement "
            "over Variant A."
        )

    elif improvement >= -0.002:

        conclusion = (
            "Performance is effectively "
            "comparable to Variant A."
        )

    else:

        conclusion = (
            "No improvement over Variant A; "
            "Variant A remains stronger."
        )

    print()

    print(
        f"Interpretation: "
        f"{conclusion}"
    )

    # --------------------------------------------------------
    # Final safety statement
    # --------------------------------------------------------

    print()
    print(
        "Test set was NOT loaded "
        "or evaluated."
    )

    print(
        "No malware samples were executed."
    )

    print()
    print(
        "Results directory:"
    )

    print(
        RESULT_DIR
    )

    print()
    print(
        "Architecture comparison:"
    )

    print(
        RESULT_DIR
        / "architecture_comparison.csv"
    )

    print("=" * 72)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
