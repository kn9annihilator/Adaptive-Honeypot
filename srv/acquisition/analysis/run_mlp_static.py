from pathlib import Path
import json
import random

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from scipy.sparse import load_npz
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

TRAIN_X = BASE / "features/pe/train.npz"
VAL_X = BASE / "features/pe/validation.npz"

TRAIN_Y = BASE / "dataset/train.csv"
VAL_Y = BASE / "dataset/validation.csv"

OUT = BASE / "results/deep_learning/static_mlp"
OUT.mkdir(parents=True, exist_ok=True)

SEED = 42

INPUT_DIM = 22
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
# Utility functions
# ============================================================

def load_features(path: Path) -> np.ndarray:
    """
    Load sparse NPZ feature matrix and convert to float32 dense array.

    PE representation is only 22 dimensions, so dense conversion is
    safe and appropriate for this experiment.
    """
    matrix = load_npz(path)
    return matrix.toarray().astype(np.float32)


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
# Load dataset
# ============================================================

print("=" * 72)
print("STATIC DEEP LEARNING — MLP")
print("=" * 72)

print("\nLoading PE feature matrices...")

X_train = load_features(TRAIN_X)
X_val = load_features(VAL_X)

train_df = pd.read_csv(TRAIN_Y)
val_df = pd.read_csv(VAL_Y)

if "family" not in train_df.columns:
    raise RuntimeError(
        f"'family' column missing from training CSV. "
        f"Columns: {list(train_df.columns)}"
    )

if "family" not in val_df.columns:
    raise RuntimeError(
        f"'family' column missing from validation CSV. "
        f"Columns: {list(val_df.columns)}"
    )

# ============================================================
# Verify dimensions
# ============================================================

if X_train.shape[1] != INPUT_DIM:
    raise RuntimeError(
        f"Expected {INPUT_DIM} PE features, got {X_train.shape[1]}"
    )

if X_val.shape[1] != INPUT_DIM:
    raise RuntimeError(
        f"Expected {INPUT_DIM} PE features, got {X_val.shape[1]}"
    )

if X_train.shape[0] != len(train_df):
    raise RuntimeError("Training feature/label row count mismatch.")

if X_val.shape[0] != len(val_df):
    raise RuntimeError("Validation feature/label row count mismatch.")

# ============================================================
# Verify SHA separation
# ============================================================

train_sha = set(train_df["sha256"])
val_sha = set(val_df["sha256"])

sha_overlap = train_sha & val_sha

if sha_overlap:
    raise RuntimeError(
        f"TRAIN/VALIDATION SHA overlap detected: {len(sha_overlap)}"
    )

# ============================================================
# Encode labels
# ============================================================

classes = sorted(
    set(train_df["family"].tolist()) |
    set(val_df["family"].tolist())
)

if len(classes) != NUM_CLASSES:
    raise RuntimeError(
        f"Expected {NUM_CLASSES} classes, found {len(classes)}: {classes}"
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
# Convert to PyTorch tensors
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

    def __init__(
        self,
        input_dim: int,
        num_classes: int,
    ):
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

# ============================================================
# Model information
# ============================================================

parameter_count = sum(
    parameter.numel()
    for parameter in model.parameters()
    if parameter.requires_grad
)

print("\nDataset:")
print(f"  Training samples:   {len(train_dataset)}")
print(f"  Validation samples: {len(val_dataset)}")
print(f"  Input dimensions:   {INPUT_DIM}")
print(f"  Classes:            {NUM_CLASSES}")

print("\nClasses:")
for idx, label in id_to_label.items():
    print(f"  {idx:2d} -> {label}")

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
# Training / validation functions
# ============================================================

def train_one_epoch(model, loader, criterion, optimizer):

    model.train()

    running_loss = 0.0
    y_true = []
    y_pred = []

    for X_batch, y_batch in loader:

        X_batch = X_batch.to(DEVICE)
        y_batch = y_batch.to(DEVICE)

        optimizer.zero_grad()

        logits = model(X_batch)

        loss = criterion(logits, y_batch)

        loss.backward()

        optimizer.step()

        running_loss += loss.item() * X_batch.size(0)

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

    epoch_loss = running_loss / len(loader.dataset)

    metrics = calculate_metrics(
        np.array(y_true),
        np.array(y_pred),
    )

    metrics["loss"] = float(epoch_loss)

    return metrics


@torch.no_grad()
def evaluate(model, loader, criterion):

    model.eval()

    running_loss = 0.0
    y_true = []
    y_pred = []

    for X_batch, y_batch in loader:

        X_batch = X_batch.to(DEVICE)
        y_batch = y_batch.to(DEVICE)

        logits = model(X_batch)

        loss = criterion(
            logits,
            y_batch,
        )

        running_loss += loss.item() * X_batch.size(0)

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

    epoch_loss = running_loss / len(loader.dataset)

    metrics = calculate_metrics(
        np.array(y_true),
        np.array(y_pred),
    )

    metrics["loss"] = float(epoch_loss)

    return metrics, np.array(y_true), np.array(y_pred)


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

    train_metrics = train_one_epoch(
        model,
        train_loader,
        criterion,
        optimizer,
    )

    val_metrics, _, _ = evaluate(
        model,
        val_loader,
        criterion,
    )

    row = {
        "epoch": epoch,

        "train_loss": train_metrics["loss"],
        "train_accuracy": train_metrics["accuracy"],
        "train_macro_precision": train_metrics["macro_precision"],
        "train_macro_recall": train_metrics["macro_recall"],
        "train_macro_f1": train_metrics["macro_f1"],
        "train_weighted_f1": train_metrics["weighted_f1"],

        "validation_loss": val_metrics["loss"],
        "validation_accuracy": val_metrics["accuracy"],
        "validation_macro_precision": val_metrics["macro_precision"],
        "validation_macro_recall": val_metrics["macro_recall"],
        "validation_macro_f1": val_metrics["macro_f1"],
        "validation_weighted_f1": val_metrics["weighted_f1"],
    }

    history.append(row)

    current_f1 = val_metrics["macro_f1"]

    if current_f1 > best_val_f1:

        best_val_f1 = current_f1
        best_epoch = epoch
        epochs_without_improvement = 0

        torch.save(
            {
                "model_state_dict": model.state_dict(),
                "classes": classes,
                "input_dim": INPUT_DIM,
                "hidden_dims": [
                    HIDDEN_1,
                    HIDDEN_2,
                    HIDDEN_3,
                ],
                "dropout": DROPOUT,
                "seed": SEED,
                "best_epoch": best_epoch,
                "best_validation_macro_f1": best_val_f1,
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
# Load best model
# ============================================================

checkpoint = torch.load(
    best_model_path,
    map_location=DEVICE,
)

model.load_state_dict(
    checkpoint["model_state_dict"]
)

# ============================================================
# Best validation evaluation
# ============================================================

val_metrics, y_val_true, y_val_pred = evaluate(
    model,
    val_loader,
    criterion,
)

print("\n" + "=" * 72)
print("BEST VALIDATION RESULT")
print("=" * 72)

print(
    f"Best epoch:       {best_epoch}"
)

print(
    f"Accuracy:         {val_metrics['accuracy']:.6f}"
)

print(
    f"Macro Precision:  {val_metrics['macro_precision']:.6f}"
)

print(
    f"Macro Recall:     {val_metrics['macro_recall']:.6f}"
)

print(
    f"Macro F1:         {val_metrics['macro_f1']:.6f}"
)

print(
    f"Weighted F1:      {val_metrics['weighted_f1']:.6f}"
)


# ============================================================
# Validation classification report
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
# Validation confusion matrix
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
# Validation predictions
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
# Save experiment configuration
# ============================================================

config = {
    "model": "StaticMLP",
    "representation": "PE",
    "input_features": INPUT_DIM,
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
        "early_stopping_metric": "validation_macro_f1",
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
    "best_validation_macro_f1": float(best_val_f1),
    "trainable_parameters": parameter_count,
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


print("\n" + "=" * 72)
print("STATIC MLP VALIDATION EXPERIMENT COMPLETE")
print("=" * 72)

print("\nArtifacts:")
for path in sorted(OUT.iterdir()):
    print(f"  {path.name}")

print(
    "\nTEST SET WAS NOT LOADED OR USED."
)
