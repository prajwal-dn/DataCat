"""DATACAT Logistic Regression Model Training Script.

Performs:
  1. Loads data/datacat_telemetry.csv.
  2. Extracts 14 causal features using app.ml.features.
  3. Chronological per-server temporal split (70% Train, 15% Validation, 15% Test).
  4. Fits Standardizer exclusively on Training split (mean/std).
  5. Fits Logistic Regression via Batch Gradient Descent with Momentum & L2 regularization.
  6. Evaluates validation performance and tunes decision threshold (maximizing F1).
  7. Evaluates unbiased out-of-sample performance on Test split.
  8. Persists trained model to JSON (app/models/logistic_regression_model.json and backend/models/logistic_regression_model.json).
  9. Prints detailed evaluation metrics and confusion matrices.

Strict Constraints:
  - Python standard library only (csv, json, math, statistics, os, sys).
  - No Pandas, NumPy, Scikit-learn, PyTorch.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.ml.features import (
    FEATURE_NAMES,
    extract_features_from_chronological_series,
)
from app.ml.logistic_regression import (
    LogisticRegressionBinaryClassifier,
    Standardizer,
)


def load_dataset(csv_path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Loads CSV and groups observations by server_id chronologically."""
    servers_data: dict[str, list[dict[str, Any]]] = {}
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sid = row["server_id"]
            if sid not in servers_data:
                servers_data[sid] = []
            servers_data[sid].append(row)
    return servers_data


def train_and_evaluate(
    csv_path: str = "data/datacat_telemetry.csv",
    save_path: str = "app/models/logistic_regression_model.json",
    backup_path: str = "backend/models/logistic_regression_model.json",
) -> dict[str, Any]:
    print("=" * 70)
    print("DATACAT AIOps — Pure-Python Logistic Regression Training Pipeline")
    print("=" * 70)

    # 1. Load data
    print(f"\n[1/6] Loading telemetry dataset from: {csv_path}")
    servers_data = load_dataset(csv_path)
    total_raw_rows = sum(len(rows) for rows in servers_data.values())
    print(f"      Loaded {total_raw_rows} records across {len(servers_data)} servers:")
    for sid, rows in servers_data.items():
        anoms = sum(1 for r in rows if int(r["is_anomaly"]) == 1)
        print(f"      - {sid}: {len(rows)} observations ({anoms} anomalous, {len(rows)-anoms} normal)")

    # 2. Extract features per server with causal time-series ordering
    print("\n[2/6] Extracting 14 causal features (zero temporal leakage)...")
    train_raw: list[list[float]] = []
    train_y: list[int] = []

    val_raw: list[list[float]] = []
    val_y: list[int] = []

    test_raw: list[list[float]] = []
    test_y: list[int] = []

    split_stats = {"train": {"normal": 0, "anom": 0}, "val": {"normal": 0, "anom": 0}, "test": {"normal": 0, "anom": 0}}

    for sid, rows in servers_data.items():
        extracted = extract_features_from_chronological_series(rows)
        n = len(extracted)

        # 70% Train, 15% Validation, 15% Test chronologically per server
        train_end = int(n * 0.70)  # e.g. 210
        val_end = int(n * 0.85)    # e.g. 255

        s_train = extracted[:train_end]
        s_val = extracted[train_end:val_end]
        s_test = extracted[val_end:]

        for item in s_train:
            train_raw.append(item["features"])
            y = item["is_anomaly"]
            train_y.append(y)
            if y == 1:
                split_stats["train"]["anom"] += 1
            else:
                split_stats["train"]["normal"] += 1

        for item in s_val:
            val_raw.append(item["features"])
            y = item["is_anomaly"]
            val_y.append(y)
            if y == 1:
                split_stats["val"]["anom"] += 1
            else:
                split_stats["val"]["normal"] += 1

        for item in s_test:
            test_raw.append(item["features"])
            y = item["is_anomaly"]
            test_y.append(y)
            if y == 1:
                split_stats["test"]["anom"] += 1
            else:
                split_stats["test"]["normal"] += 1

    print(f"      - Training Split:   {len(train_raw)} samples ({split_stats['train']['anom']} anomalous, {split_stats['train']['normal']} normal)")
    print(f"      - Validation Split: {len(val_raw)} samples ({split_stats['val']['anom']} anomalous, {split_stats['val']['normal']} normal)")
    print(f"      - Testing Split:    {len(test_raw)} samples ({split_stats['test']['anom']} anomalous, {split_stats['test']['normal']} normal)")

    # 3. Train Logistic Regression
    print("\n[3/6] Fitting Feature Standardizer & Training Logistic Regression...")
    model = LogisticRegressionBinaryClassifier(
        feature_names=FEATURE_NAMES,
        model_version="1.0.0",
    )

    fit_results = model.fit(
        X_train_raw=train_raw,
        y_train=train_y,
        learning_rate=0.08,
        iterations=2000,
        l2_lambda=0.005,
        momentum=0.9,
        class_weight="balanced",
    )
    print(f"      Training completed: 2000 epochs, Final BCE Loss: {fit_results['final_loss']:.5f}")

    # 4. Tune decision threshold on Validation Set
    print("\n[4/6] Selecting classification threshold on Validation Split (maximizing F1)...")
    best_threshold = model.select_threshold_on_validation(val_raw, val_y, metric="f1")
    print(f"      Optimal Validation Threshold selected: {best_threshold:.2f}")

    # 5. Comprehensive Multi-Split Evaluation
    print("\n[5/6] Evaluating Model Performance across Splits...")
    train_eval = model.evaluate_dataset(train_raw, train_y, threshold=best_threshold)
    val_eval = model.evaluate_dataset(val_raw, val_y, threshold=best_threshold)
    test_eval = model.evaluate_dataset(test_raw, test_y, threshold=best_threshold)

    # Attach metadata to model
    model.training_metadata = {
        "dataset_path": str(csv_path),
        "dataset_total_samples": total_raw_rows,
        "split_counts": {
            "train": {"total": len(train_raw), "anomalous": split_stats["train"]["anom"], "normal": split_stats["train"]["normal"]},
            "validation": {"total": len(val_raw), "anomalous": split_stats["val"]["anom"], "normal": split_stats["val"]["normal"]},
            "test": {"total": len(test_raw), "anomalous": split_stats["test"]["anom"], "normal": split_stats["test"]["normal"]},
        },
        "evaluation_metrics": {
            "train": train_eval,
            "validation": val_eval,
            "test": test_eval,
        },
    }

    # 6. Save model to JSON
    print(f"\n[6/6] Saving trained model to disk:")
    model.save(save_path)
    print(f"      -> Primary: {save_path}")
    if backup_path:
        model.save(backup_path)
        print(f"      -> Backup:  {backup_path}")

    # Print Report
    print("\n" + "=" * 70)
    print("MODEL EVALUATION REPORT")
    print("=" * 70)
    print(f"Feature Vector Dimension: {len(FEATURE_NAMES)}")
    print(f"Decision Threshold:       {model.threshold:.2f}")
    print(f"Intercept / Bias:         {model.intercept:.5f}")
    print("\nFeature Weights (Top Impact):")
    sorted_weights = sorted(zip(FEATURE_NAMES, model.weights), key=lambda x: abs(x[1]), reverse=True)
    for name, w in sorted_weights:
        sign = "+" if w >= 0 else "-"
        print(f"  {sign} {name:<26} : {w:>9.5f}")

    for split_name, ev in [("TRAINING (70%)", train_eval), ("VALIDATION (15%)", val_eval), ("TESTING (15% Unseen)", test_eval)]:
        print(f"\n--- {split_name} ---")
        print(f"  Samples:    {ev['samples']}")
        print(f"  Accuracy:   {ev['accuracy']*100:.2f}%")
        print(f"  Precision:  {ev['precision']*100:.2f}%")
        print(f"  Recall:     {ev['recall']*100:.2f}%")
        print(f"  F1-Score:   {ev['f1_score']:.4f}")
        print("  Confusion Matrix:")
        print(f"               Actual Normal   Actual Anomaly")
        print(f"  Pred Normal: {ev['true_negatives']:>13}   {ev['false_negatives']:>14}")
        print(f"  Pred Anomaly:{ev['false_positives']:>13}   {ev['true_positives']:>14}")

    print("=" * 70)
    return {
        "model": model,
        "train_eval": train_eval,
        "val_eval": val_eval,
        "test_eval": test_eval,
    }


if __name__ == "__main__":
    train_and_evaluate()
