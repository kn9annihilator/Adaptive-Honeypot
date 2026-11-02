#!/usr/bin/env python3

from pathlib import Path
import json
import random

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from scipy.sparse import load_npz, hstack
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from torch.utils.data import DataLoader, TensorDataset


# ============================================================
# Configuration
# ============================================================

BASE = Path("/srv/acquisition/analysis")

PE_TRAIN = BASE / "features/pe/train.npz"
PE_VAL = BASE / "features/pe/validation.npz"

DLL_TRAIN = BASE / "features/dll/train.npz"
DLL_VAL = BASE / "features/dll/validation.npz"

TRAIN_Y = BASE / "dataset/train.csv"
VAL_Y = BASE / "dataset/validation.csv"

OUT = BASE / "results/deep_learning/static_mlp/pe_dll"
OUT.mkdir(parents=True, exist_ok=True)

SEED = 42

PE_DIM = 22
DLL_DIM = 78
INPUT_DIM = PE_DIM + DLL_DIM
NUM_CLASSES = 12

HIDDEN_1 = 128
HIDDEN_2 = 64
HIDDEN_3 = 32

DROPOUT = 0.30

LEARNING_RATE = 1e-3
BATCH_SIZE = 32
MAX_EPOCHS = 100
PATIENCE = 15

DEVICE = torch.device("cpu")


# ============================================================
# Reproducibility
# ============================================================

def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)

    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


set_seed(SEED)


# ============================================================
# Metrics
# ============================================================

def calculate_metrics(y_true, y_pred):

    accuracy = accuracy_score(y_true, y_pred)

    macro_precision, macro_recall, macro_f1, _ = (
        precision_recall_fscore_support(
            y_true,
            y_pred,
            average="macro",
            zero_division=0,
        )
    )

    weighted_precision, weighted_recall, weighted_f1, _ = (
        precision_recall_fscore_support(
            y_true,
            y_pred,
            average="weighted",
            zero_division=0,
        )
    )

    return {
        "accuracy": float(accuracy),
        "macro_precision": float(macro_precision),
        "macro_recall": float(macro_recall),
        "macro_f1": float(macro_f1),
        "weighted_precision": float(weighted_precision),
        "weighted_recall": float(weighted_recall),
        "weighted_f1": float(weighted_f1),
    }


# ============================================================
# Load and combine features
# ============================================================

print("=" * 72)
print("STATIC DEEP LEARNING — MLP + PE + DLL")
print("=" * 72)

print("\nLoading PE and DLL feature matrices...")

pe_train = load_npz(PE_TRAIN)
pe_val = load_npz(PE_VAL)

dll_train = load_npz(DLL_TRAIN)
dll_val = load_npz(DLL_VAL)

if pe_train.shape[1] != PE_DIM:
    raise RuntimeError(
        f"Expected {PE_DIM} PE features, "
        f"got {pe_train.shape[1]}"
    )

if pe_val.shape[1] != PE_DIM:
    raise RuntimeError(
        f"Expected {PE_DIM} PE validation features, "
        f"got {pe_val.shape[1]}"
    )

if dll_train.shape[1] != DLL_DIM:
    raise RuntimeError(
        f"Expected {DLL_DIM} DLL features, "
        f"got {dll_train.shape[1]}"
    )

if dll_val.shape[1] != DLL_DIM:
    raise RuntimeError(
        f"Expected {DLL_DIM} DLL validation features, "
        f"got {dll_val.shape[1]}"
    )

if pe_train.shape[0] != dll_train.shape[0]:
    raise RuntimeError("Training PE/DLL row mismatch.")

if pe_val.shape[0] != dll_val.shape[0]:
    raise RuntimeError("Validation PE/DLL row mismatch.")

X_train_sparse = hstack(
    [pe_train, dll_train],
    format="csr",
)

X_val_sparse = hstack(
    [pe_val, dll_val],
    format="csr",
)

X_train = X_train_sparse.toarray().astype(np.float32)
X_val = X_val_sparse.toarray().astype(np.float32)

del pe_train, pe_val, dll_train, dll_val
del X_train_sparse, X_val_sparse


# ============================================================
# Load labels
# ============================================================

train_df = pd.read_csv(TRAIN_Y)
val_df = pd.read_csv(VAL_Y)

if "family" not in train_df.columns:
    raise RuntimeError("'family' column missing from training CSV.")

if "family" not in val_df.columns:
    raise RuntimeError("'family' column missing from validation CSV.")

if X_train.shape[0] != len(train_df):
    raise RuntimeError("Training feature/label row mismatch.")

if X_val.shape[0] != len(val_df):
    raise RuntimeError("Validation feature/label row mismatch.")


# ============================================================
# Verify SHA separation
# ============================================================

train_sha = set(train_df["sha256"])
val_sha = set(val_df["sha256"])

sha_overlap = train_sha & val_sha

if sha_overlap:
    raise RuntimeError(
        f"TRAIN/VALIDATION SHA overlap detected: "
        f"{len(sha_overlap)}"
    )


# ============================================================
# Encode labels
# ============================================================

classes = sorted(
    set(train_df["family"].tolist())
    |
    set(val_df["family"].tolist())
)

if len(classes) != NUM_CLASSES:
    raise RuntimeError(
        f"Expected {NUM_CLASSES} classes, "
        f"found {len(classes)}: {classes}"
    )

label_to_id = {
    label: idx
    for idx, label in enumerate(classes)
}

id_to_label = {
    idx: label
    for label, idx in label_to_id.items()
}

y_train = np.array(
    [label_to_id[label] for label in train_df["family"]],
    dtype=np.int64,
)

y_val = np.array(
    [label_to_id[label] for label in val_df["family"]],
    dtype=np.int64,
)


# ============================================================
# Tensor datasets
# ============================================================

X_train_tensor = torch.from_numpy(X_train)
y_train_tensor = torch.from_numpy(y_train)

X_val_tensor = torch.from_numpy(X_val)
y_val_tensor = torch.from_numpy(y_val)

train_dataset = TensorDataset(
    X_train_tensor,
    y_train_tensor,
)

val_dataset = TensorDataset(
    X_val_tensor,
    y_val_tensor,
)

train_loader = DataLoader(
    train_dataset,
    batch_size=BATCH_SIZE,
    shuffle=True,
    num_workers=0,
)

val_loader = DataLoader(
    val_dataset,
    batch_size=BATCH_SIZE,
    shuffle=False,
    num_workers=0,
)


# ============================================================
# Model
# ============================================================

class StaticMLP(nn.Module):

    def __init__(self, input_dim, num_classes):

        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(input_dim, HIDDEN_1),
            nn.ReLU(),
            nn.Dropout(DROPOUT),

            nn.Linear(HIDDEN_1, HIDDEN_2),
            nn.ReLU(),
            nn.Dropout(DROPOUT),

            nn.Linear(HIDDEN_2, HIDDEN_3),
            nn.ReLU(),

            nn.Linear(HIDDEN_3, num_classes),
        )

    def forward(self, x):
        return self.network(x)


model = StaticMLP(
    input_dim=INPUT_DIM,
    num_classes=NUM_CLASSES,
).to(DEVICE)

criterion = nn.CrossEntropyLoss()

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE,
)

parameter_count = sum(
    p.numel()
    for p in model.parameters()
    if p.requires_grad
)


# ============================================================
# Information
# ============================================================

print("\nDataset:")
print(f"  Training samples:   {len(train_dataset)}")
print(f"  Validation samples: {len(val_dataset)}")
print(f"  PE features:        {PE_DIM}")
print(f"  DLL features:       {DLL_DIM}")
print(f"  Combined features:  {INPUT_DIM}")
print(f"  Classes:            {NUM_CLASSES}")

print("\nModel:")
print(model)

print(f"\nTrainable parameters: {parameter_count:,}")

print("\nTraining configuration:")
print(f"  Device:          {DEVICE}")
print(f"  Learning rate:   {LEARNING_RATE}")
print(f"  Batch size:      {BATCH_SIZE}")
print(f"  Maximum epochs:  {MAX_EPOCHS}")
print(f"  Early stopping:  {PATIENCE} epochs")
print(f"  Dropout:         {DROPOUT}")
print(f"  Random seed:     {SEED}")


# ============================================================
# Training
# ============================================================

def train_one_epoch():

    model.train()

    running_loss = 0.0
    y_true = []
    y_pred = []

    for X_batch, y_batch in train_loader:

        X_batch = X_batch.to(DEVICE)
        y_batch = y_batch.to(DEVICE)

        optimizer.zero_grad()

        logits = model(X_batch)

        loss = criterion(
            logits,
            y_batch,
        )

        loss.backward()

        optimizer.step()

        running_loss += (
            loss.item()
            *
            X_batch.size(0)
        )

        predictions = torch.argmax(
            logits,
            dim=1,
        )

        y_true.extend(
            y_batch.detach().cpu().numpy()
        )

        y_pred.extend(
            predictions.detach().cpu().numpy()
        )

    metrics = calculate_metrics(
        np.array(y_true),
        np.array(y_pred),
    )

    metrics["loss"] = (
        running_loss
        /
        len(train_loader.dataset)
    )

    return metrics


@torch.no_grad()
def evaluate():

    model.eval()

    running_loss = 0.0
    y_true = []
    y_pred = []

    for X_batch, y_batch in val_loader:

        X_batch = X_batch.to(DEVICE)
        y_batch = y_batch.to(DEVICE)

        logits = model(X_batch)

        loss = criterion(
            logits,
            y_batch,
        )

        running_loss += (
            loss.item()
            *
            X_batch.size(0)
        )

        predictions = torch.argmax(
            logits,
            dim=1,
        )

        y_true.extend(
            y_batch.cpu().numpy()
        )

        y_pred.extend(
            predictions.cpu().numpy()
        )

    metrics = calculate_metrics(
        np.array(y_true),
        np.array(y_pred),
    )

    metrics["loss"] = (
        running_loss
        /
        len(val_loader.dataset)
    )

    return (
        metrics,
        np.array(y_true),
        np.array(y_pred),
    )


# ============================================================
# Training loop
# ============================================================

history = []

best_val_f1 = -np.inf
best_epoch = 0
epochs_without_improvement = 0

best_model_path = OUT / "best_model.pt"

print("\n" + "=" * 72)
print("TRAINING")
print("=" * 72)

for epoch in range(1, MAX_EPOCHS + 1):

    train_metrics = train_one_epoch()

    val_metrics, _, _ = evaluate()

    history.append({
        "epoch": epoch,

        "train_loss": train_metrics["loss"],
        "train_accuracy": train_metrics["accuracy"],
        "train_macro_precision":
            train_metrics["macro_precision"],
        "train_macro_recall":
            train_metrics["macro_recall"],
        "train_macro_f1":
            train_metrics["macro_f1"],
        "train_weighted_f1":
            train_metrics["weighted_f1"],

        "validation_loss":
            val_metrics["loss"],
        "validation_accuracy":
            val_metrics["accuracy"],
        "validation_macro_precision":
            val_metrics["macro_precision"],
        "validation_macro_recall":
            val_metrics["macro_recall"],
        "validation_macro_f1":
            val_metrics["macro_f1"],
        "validation_weighted_f1":
            val_metrics["weighted_f1"],
    })

    current_f1 = val_metrics["macro_f1"]

    if current_f1 > best_val_f1:

        best_val_f1 = current_f1
        best_epoch = epoch
        epochs_without_improvement = 0

        torch.save(
            {
                "model_state_dict":
                    model.state_dict(),
                "classes":
                    classes,
                "input_dim":
                    INPUT_DIM,
                "pe_dim":
                    PE_DIM,
                "dll_dim":
                    DLL_DIM,
                "hidden_dims": [
                    HIDDEN_1,
                    HIDDEN_2,
                    HIDDEN_3,
                ],
                "dropout":
                    DROPOUT,
                "seed":
                    SEED,
                "best_epoch":
                    best_epoch,
                "best_validation_macro_f1":
                    best_val_f1,
            },
            best_model_path,
        )

    else:
        epochs_without_improvement += 1

    print(
        f"Epoch {epoch:03d} | "
        f"Train Loss {train_metrics['loss']:.4f} | "
        f"Train F1 {train_metrics['macro_f1']:.4f} | "
        f"Val Loss {val_metrics['loss']:.4f} | "
        f"Val F1 {val_metrics['macro_f1']:.4f}"
    )

    if epochs_without_improvement >= PATIENCE:

        print(
            f"\nEarly stopping at epoch {epoch}. "
            f"Best epoch: {best_epoch}"
        )

        break


# ============================================================
# Save training history
# ============================================================

history_df = pd.DataFrame(history)

history_df.to_csv(
    OUT / "training_history.csv",
    index=False,
)


# ============================================================
# Restore best model
# ============================================================

checkpoint = torch.load(
    best_model_path,
    map_location=DEVICE,
)

model.load_state_dict(
    checkpoint["model_state_dict"]
)


# ============================================================
# Final validation evaluation
# ============================================================

val_metrics, y_val_true, y_val_pred = evaluate()

print("\n" + "=" * 72)
print("BEST VALIDATION RESULT")
print("=" * 72)

print(f"Best epoch:       {best_epoch}")
print(
    f"Accuracy:         "
    f"{val_metrics['accuracy']:.6f}"
)
print(
    f"Macro Precision:  "
    f"{val_metrics['macro_precision']:.6f}"
)
print(
    f"Macro Recall:     "
    f"{val_metrics['macro_recall']:.6f}"
)
print(
    f"Macro F1:         "
    f"{val_metrics['macro_f1']:.6f}"
)
print(
    f"Weighted F1:      "
    f"{val_metrics['weighted_f1']:.6f}"
)


# ============================================================
# Classification report
# ============================================================

validation_report = classification_report(
    y_val_true,
    y_val_pred,
    labels=list(range(NUM_CLASSES)),
    target_names=classes,
    output_dict=True,
    zero_division=0,
)

with open(
    OUT / "validation_classification_report.json",
    "w",
) as f:

    json.dump(
        validation_report,
        f,
        indent=2,
    )


# ============================================================
# Confusion matrix
# ============================================================

validation_cm = confusion_matrix(
    y_val_true,
    y_val_pred,
    labels=list(range(NUM_CLASSES)),
)

validation_cm_df = pd.DataFrame(
    validation_cm,
    index=classes,
    columns=classes,
)

validation_cm_df.index.name = "actual"

validation_cm_df.to_csv(
    OUT / "validation_confusion_matrix.csv"
)


# ============================================================
# Predictions
# ============================================================

validation_predictions = val_df.copy()

validation_predictions[
    "predicted_family"
] = [
    id_to_label[int(pred)]
    for pred in y_val_pred
]

validation_predictions[
    "correct"
] = (
    validation_predictions["family"]
    ==
    validation_predictions["predicted_family"]
)

validation_predictions.to_csv(
    OUT / "validation_predictions.csv",
    index=False,
)


# ============================================================
# Configuration
# ============================================================

config = {
    "model": "StaticMLP",
    "representation": "PE+DLL",

    "input_features": INPUT_DIM,
    "pe_features": PE_DIM,
    "dll_features": DLL_DIM,

    "num_classes": NUM_CLASSES,

    "architecture": {
        "hidden_layers": [
            HIDDEN_1,
            HIDDEN_2,
            HIDDEN_3,
        ],
        "activation": "ReLU",
        "dropout": DROPOUT,
        "output": "12-class logits",
    },

    "training": {
        "optimizer": "Adam",
        "learning_rate": LEARNING_RATE,
        "loss": "CrossEntropyLoss",
        "batch_size": BATCH_SIZE,
        "max_epochs": MAX_EPOCHS,
        "early_stopping_patience": PATIENCE,
        "early_stopping_metric":
            "validation_macro_f1",
    },

    "reproducibility": {
        "seed": SEED,
        "device": str(DEVICE),
    },

    "dataset": {
        "train_samples": len(train_dataset),
        "validation_samples": len(val_dataset),
        "test_used": False,
    },

    "best_epoch": best_epoch,
    "best_validation_macro_f1":
        float(best_val_f1),
    "trainable_parameters":
        parameter_count,
}

with open(
    OUT / "experiment_config.json",
    "w",
) as f:

    json.dump(
        config,
        f,
        indent=2,
    )


# ============================================================
# Complete
# ============================================================

print("\n" + "=" * 72)
print("STATIC MLP + PE + DLL EXPERIMENT COMPLETE")
print("=" * 72)

print("\nArtifacts:")

for path in sorted(OUT.iterdir()):
    print(f"  {path.name}")

print("\nTEST SET WAS NOT LOADED OR USED.")
