# DATACAT Synthetic Telemetry Dataset Documentation

## Overview

The `data/datacat_telemetry.csv` dataset is a realistic, labeled time-series dataset designed for research, training, and evaluation of DATACAT's Tier 2 AIOps machine learning models (specifically pure-Python Logistic Regression and statistical anomaly detection engines).

This dataset was generated using only the Python standard library (`csv`, `random`, `datetime`, `statistics`) with a deterministic fixed random seed (`42`) to guarantee 100% reproducibility across environments.

---

## Dataset Specifications

| Metric / Property | Specification |
| :--- | :--- |
| **Filename** | `data/datacat_telemetry.csv` |
| **Generator Script** | `scripts/generate_telemetry_data.py` |
| **Total Rows** | 900 records (+ 1 header row) |
| **Total Servers** | 3 simulated hospital infrastructure nodes (300 records each) |
| **Time Granularity** | 1-minute sequential intervals (300 minutes = 5 hours per server) |
| **Time Horizon** | `2026-11-20T00:00:00Z` to `2026-11-20T04:59:00Z` |
| **Target Variable** | `is_anomaly` (Binary: `0` = Normal, `1` = Anomaly) |
| **Multi-class Descriptor** | `anomaly_type` (7 distinct categories) |
| **Class Distribution** | 720 Normal (80.0%), 180 Anomalous (20.0%) |
| **File Size** | 67,973 bytes (~66.38 KB) |

---

## Schema & Field Definitions

| Column Name | Data Type | Nullable | Valid Range | Description |
| :--- | :--- | :--- | :--- | :--- |
| `timestamp_utc` | `str` (ISO 8601) | No | `YYYY-MM-DDTHH:MM:SSZ` | Canonical UTC timestamp of the observation. |
| `server_id` | `str` | No | Known server identifier | Unique identifier of the monitored host server. |
| `cpu_usage` | `float` | No | `0.0` - `100.0` (%) | Total processor utilization percentage. |
| `memory_usage` | `float` | No | `0.0` - `100.0` (%) | RAM consumption percentage. |
| `disk_usage` | `float` | No | `0.0` - `100.0` (%) | Primary storage partition utilization percentage. |
| `latency_ms` | `float` | No | `>= 0.0` (ms) | Round-trip network / ping response time. |
| `is_anomaly` | `int` | No | `0` or `1` | Binary ground-truth label for supervised learning. |
| `anomaly_type` | `str` | No | Enum (7 types) | Descriptive category explaining the root cause/pattern. |

---

## Server Baseline Profiles

Each server simulates a specialized clinical computing workload with distinctive operating baselines and standard deviations:

### 1. `hospital_server_01` — Intensive Care Unit (ICU) Telemetry Node
- **Role**: Ingests real-time continuous physiological patient monitor data.
- **Normal Operating Baselines**:
  - CPU: Mean `32.0%` (Std: `4.5%`)
  - Memory: Mean `52.0%` (Std: `3.0%`)
  - Disk: Mean `42.0%` (Std: `0.8%`)
  - Latency: Mean `12.0 ms` (Std: `2.2 ms`)

### 2. `hospital_server_02` — Electronic Health Record (EHR) Central Database
- **Role**: Relational patient database managing concurrent doctor lookups, billing, and order entries.
- **Normal Operating Baselines**:
  - CPU: Mean `45.0%` (Std: `5.5%`)
  - Memory: Mean `68.0%` (Std: `3.5%`)
  - Disk: Mean `62.0%` (Std: `1.2%`)
  - Latency: Mean `20.0 ms` (Std: `3.2 ms`)

### 3. `hospital_server_03` — Radiology PACS Imaging Server
- **Role**: Archives and serves volumetric MRI/CT DICOM imaging studies.
- **Normal Operating Baselines**:
  - CPU: Mean `28.0%` (Std: `4.8%`)
  - Memory: Mean `58.0%` (Std: `4.0%`)
  - Disk: Mean `76.0%` (Std: `1.5%`)
  - Latency: Mean `18.0 ms` (Std: `2.8 ms`)

---

## Anomaly Distribution Breakdown

The dataset contains a balanced 80/20 distribution representing typical operational environments where anomalies are infrequent but critical.

| Anomaly Type | Total Count | % of Dataset | Description / Real-World Clinical Context |
| :--- | :---: | :---: | :--- |
| `normal` | **720** | **80.0%** | Uncompromised operational state with natural stochastic jitter. |
| `cpu_spike` | **24** | **2.7%** | Intensive cryptographic batch jobs, unoptimized rendering queries, or runaway worker loops. |
| `memory_spike` | **24** | **2.7%** | Buffer cache blowouts, uncollected object cycles, or rapid RAM leak. |
| `disk_pressure` | **24** | **2.7%** | Unrotated audit logs, large temporary database dump, or DICOM imaging backlog. |
| `latency_spike` | **30** | **3.3%** | Switch packet loss, interface queue drops, or transient routing saturation. |
| `resource_contention` | **45** | **5.0%** | Severe multi-metric bottleneck: CPU, memory, and latency degraded simultaneously. |
| `gradual_degradation` | **33** | **3.7%** | Slow multi-step resource leak progressing monotonically across 11 consecutive minutes. |
| **Total** | **900** | **100.0%** | **720 Normal, 180 Anomalous** |

---

## Server Breakdown

| Server ID | Total Records | Normal (`0`) | Anomalies (`1`) | Anomaly Ratio |
| :--- | :---: | :---: | :---: | :---: |
| `hospital_server_01` | 300 | 240 | 60 | 20.0% |
| `hospital_server_02` | 300 | 240 | 60 | 20.0% |
| `hospital_server_03` | 300 | 240 | 60 | 20.0% |
| **Total** | **900** | **720** | **180** | **20.0%** |

---

## Reproducibility & Regeneration

To regenerate this dataset identically at any time:

```bash
python scripts/generate_telemetry_data.py
```

Because the generator relies purely on Python's built-in `random.seed(42)`, the output CSV is byte-for-byte deterministic across platforms.
