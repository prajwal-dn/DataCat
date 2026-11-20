"""Script to evaluate both Statistical and ML models on data/datacat_telemetry.csv
and measure precise processing times.

Strict constraints:
  - Python standard library only (csv, json, time, math, statistics).
  - Zero external ML frameworks.
"""

from __future__ import annotations

import csv
import json
import math
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.core.detection_config import DetectionConfig
from app.core.statistical_detector import (
    MONITORED_METRICS,
    _classify_metric,
    _compute_statistical_context,
)
from app.ml.features import extract_features_from_chronological_series
from app.ml.logistic_regression import LogisticRegressionBinaryClassifier, Standardizer
from app.ml.inference import get_model


def load_dataset(csv_path: str | Path = "data/datacat_telemetry.csv") -> dict[str, list[dict[str, Any]]]:
    servers_data: dict[str, list[dict[str, Any]]] = {}
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sid = row["server_id"]
            if sid not in servers_data:
                servers_data[sid] = []
            servers_data[sid].append(row)
    return servers_data


def evaluate_statistical_detector(servers_data: dict[str, list[dict[str, Any]]], cfg: DetectionConfig):
    print("=" * 70)
    print("STATISTICAL ANOMALY DETECTOR EVALUATION (900 Observations)")
    print("=" * 70)

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    # For detection delay tracking
    # Group consecutive anomaly sequences per server
    detection_delays: dict[str, list[int]] = {
        "cpu_spike": [],
        "memory_spike": [],
        "disk_pressure": [],
        "latency_spike": [],
        "resource_contention": [],
        "gradual_degradation": [],
    }

    stat_times = []

    for sid, rows in servers_data.items():
        metric_histories: dict[str, list[float]] = {m: [] for m in MONITORED_METRICS}
        persistence_tracker: dict[str, int] = {m: 0 for m in MONITORED_METRICS}
        in_sequence = False
        seq_type = ""
        seq_start_idx = 0
        detected_in_seq = False

        for i, row in enumerate(rows):
            actual_anom = int(row["is_anomaly"]) == 1
            anom_type = row.get("anomaly_type", "normal")

            # Sequence tracking for detection delay
            if actual_anom and not in_sequence:
                in_sequence = True
                seq_type = anom_type
                seq_start_idx = i
                detected_in_seq = False
            elif not actual_anom and in_sequence:
                if not detected_in_seq and seq_type in detection_delays:
                    # Missed sequence: delay is sequence length
                    detection_delays[seq_type].append(i - seq_start_idx)
                in_sequence = False
                seq_type = ""

            # Measure statistical detector execution time
            t0 = time.perf_counter()
            is_any_anom = False
            for m in MONITORED_METRICS:
                val = float(row[m])
                hist = metric_histories[m][-cfg.rolling_window_size:]
                ctx = _compute_statistical_context(m, val, hist, cfg)
                p_cnt = persistence_tracker[m]
                classified = _classify_metric(
                    m, val, ctx, p_cnt, cfg, sid, "eval_tenant", f"eval_{sid}_{i}", row["timestamp_utc"]
                )
                if classified["is_anomaly"]:
                    is_any_anom = True
                    persistence_tracker[m] = p_cnt + 1
                else:
                    persistence_tracker[m] = 0

                # Contamination guard: append clean history
                if not cfg.exclude_anomalies_from_baseline or not classified["is_anomaly"]:
                    metric_histories[m].append(val)
                elif not cfg.exclude_anomalies_from_baseline:
                    metric_histories[m].append(val)

            t1 = time.perf_counter()
            stat_times.append((t1 - t0) * 1000)  # ms

            pred_anom = is_any_anom

            if actual_anom and pred_anom:
                tp += 1
                if in_sequence and not detected_in_seq:
                    delay = i - seq_start_idx
                    if seq_type in detection_delays:
                        detection_delays[seq_type].append(delay)
                    detected_in_seq = True
            elif actual_anom and not pred_anom:
                fn += 1
            elif not actual_anom and pred_anom:
                fp += 1
            else:
                tn += 1

        # End of server series sequence check
        if in_sequence and not detected_in_seq and seq_type in detection_delays:
            detection_delays[seq_type].append(len(rows) - seq_start_idx)

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    print(f"Total Observations:    {total}")
    print(f"True Positives (TP):   {tp}")
    print(f"False Positives (FP):  {fp}")
    print(f"False Negatives (FN):  {fn}")
    print(f"True Negatives (TN):   {tn}")
    print(f"Accuracy:              {accuracy * 100:.2f}%")
    print(f"Precision:             {precision * 100:.2f}%")
    print(f"Recall:                {recall * 100:.2f}%")
    print(f"F1-Score:              {f1:.4f}")
    print("\nConfusion Matrix (Statistical Detector):")
    print(f"               Actual Normal   Actual Anomaly")
    print(f"  Pred Normal:    {tn:12d}     {fn:14d}")
    print(f"  Pred Anomaly:   {fp:12d}     {tp:14d}")

    print("\nDetection Delay by Anomaly Type (observations / minutes):")
    for atype, delays in detection_delays.items():
        if delays:
            avg_delay = statistics.mean(delays)
            max_delay = max(delays)
            min_delay = min(delays)
            print(f"  - {atype:22s}: mean = {avg_delay:.2f} obs ({avg_delay:.1f}m), min = {min_delay}, max = {max_delay}")
        else:
            print(f"  - {atype:22s}: N/A (no sequences)")

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy,
        "detection_delays": detection_delays,
        "stat_times_ms": stat_times,
    }


def evaluate_logistic_regression_splits(servers_data: dict[str, list[dict[str, Any]]]):
    print("\n" + "=" * 70)
    print("LOGISTIC REGRESSION EVALUATION (Chronological Train/Val/Test Splits)")
    print("=" * 70)

    model = get_model()

    train_data = []
    val_data = []
    test_data = []

    for sid, rows in servers_data.items():
        extracted = extract_features_from_chronological_series(rows)
        n = len(extracted)
        train_end = int(n * 0.70)
        val_end = int(n * 0.85)
        train_data.extend(extracted[:train_end])
        val_data.extend(extracted[train_end:val_end])
        test_data.extend(extracted[val_end:])

    splits = [("TRAINING (70%)", train_data), ("VALIDATION (15%)", val_data), ("TESTING (15% Unseen)", test_data)]
    results = {}
    ml_times = []

    for name, data in splits:
        tp = fp = fn = tn = 0
        for item in data:
            feats = item["features"]
            y = item["is_anomaly"]

            t0 = time.perf_counter()
            prob, pred = model.predict_one(feats)
            t1 = time.perf_counter()
            ml_times.append((t1 - t0) * 1000)

            if y == 1 and pred == 1:
                tp += 1
            elif y == 1 and pred == 0:
                fn += 1
            elif y == 0 and pred == 1:
                fp += 1
            else:
                tn += 1

        total = tp + fp + fn + tn
        acc = (tp + tn) / total if total > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        print(f"\n--- {name} ---")
        print(f"  Samples:     {total}")
        print(f"  Accuracy:    {acc * 100:.2f}%")
        print(f"  Precision:   {prec * 100:.2f}%")
        print(f"  Recall:      {rec * 100:.2f}%")
        print(f"  F1-Score:    {f1:.4f}")
        print(f"  Confusion Matrix:")
        print(f"               Actual Normal   Actual Anomaly")
        print(f"  Pred Normal:    {tn:12d}     {fn:14d}")
        print(f"  Pred Anomaly:   {fp:12d}     {tp:14d}")

        results[name] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "accuracy": acc, "precision": prec, "recall": rec, "f1": f1}

    return results, ml_times


def benchmark_performance(stat_times: list[float], ml_times: list[float]):
    print("\n" + "=" * 70)
    print("PERFORMANCE BENCHMARK (900 Synthetic Telemetry Records)")
    print("=" * 70)

    import sqlite3
    db_path = BASE_DIR / "datacat.db"
    query_times = []
    if db_path.exists():
        con = sqlite3.connect(str(db_path))
        cur = con.cursor()
        for _ in range(100):
            t0 = time.perf_counter()
            cur.execute("SELECT metrics, timestamp_utc FROM telemetry_events ORDER BY timestamp_utc DESC LIMIT 30;")
            _ = cur.fetchall()
            t1 = time.perf_counter()
            query_times.append((t1 - t0) * 1000)
        con.close()

    # Combined inference time = stat + ML
    combined_times = [s + m for s, m in zip(stat_times[:len(ml_times)], ml_times)]

    def summarize(vals: list[float], name: str):
        mean_v = statistics.mean(vals)
        median_v = statistics.median(vals)
        p95_v = sorted(vals)[int(len(vals) * 0.95)]
        min_v = min(vals)
        max_v = max(vals)
        print(f"{name:35s}: Mean={mean_v:.4f}ms | Median={median_v:.4f}ms | P95={p95_v:.4f}ms | Min={min_v:.4f}ms | Max={max_v:.4f}ms")

    summarize(stat_times, "Statistical Detection Time")
    summarize(ml_times, "Logistic Regression Inference Time")
    summarize(combined_times, "Combined AIOps Pipeline Time")
    if query_times:
        summarize(query_times, "Database History Query Time (SQLite)")


if __name__ == "__main__":
    cfg = DetectionConfig.load()
    servers_data = load_dataset()
    stat_res = evaluate_statistical_detector(servers_data, cfg)
    ml_res, ml_times = evaluate_logistic_regression_splits(servers_data)
    benchmark_performance(stat_res["stat_times_ms"], ml_times)
