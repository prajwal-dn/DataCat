"""
DATACAT Telemetry Synthetic Dataset Generator
Author: Senior Data Scientist - DATACAT Tier 2 AIOps
Description: Generates realistic synthetic labeled time-series telemetry for
             training and evaluating Logistic Regression anomaly classification models.

Strict Constraints:
- Uses ONLY Python standard library: csv, random, datetime, statistics, os, sys.
- Fixed random seed for 100% deterministic reproducibility.
- Chronological ordering per server.
- Realistic baselines, bounded metrics, and diverse anomaly patterns.
"""

import csv
import os
import random
from datetime import datetime, timedelta, timezone


def generate_dataset(output_path: str = "data/datacat_telemetry.csv") -> dict:
    # 1. Enforce strict deterministic reproducibility
    random.seed(42)

    # Base start timestamp (UTC)
    start_time = datetime(2026, 11, 20, 0, 0, 0, tzinfo=timezone.utc)
    step_minutes = 1
    records_per_server = 300

    # Server profiles: realistic hospital infrastructure baselines
    server_profiles = {
        "hospital_server_01": {
            "role": "ICU Real-time Telemetry Processing Node",
            "base_cpu": 32.0,
            "std_cpu": 4.5,
            "base_mem": 52.0,
            "std_mem": 3.0,
            "base_disk": 42.0,
            "std_disk": 0.8,
            "base_lat": 12.0,
            "std_lat": 2.2,
            # Anomaly injection schedule: (start_idx, end_idx_inclusive, anomaly_type)
            "anomalies": [
                (40, 41, "cpu_spike"),             # 2 isolated spikes
                (95, 104, "cpu_spike"),            # 10 sustained high CPU
                (150, 161, "memory_spike"),        # 12 memory leak / surge
                (205, 214, "latency_spike"),       # 10 network jitter / switch drops
                (250, 264, "resource_contention"), # 15 multi-signal bottleneck
                (280, 290, "gradual_degradation"), # 11 progressive climb
            ]
        },
        "hospital_server_02": {
            "role": "Electronic Health Record (EHR) Central Database",
            "base_cpu": 45.0,
            "std_cpu": 5.5,
            "base_mem": 68.0,
            "std_mem": 3.5,
            "base_disk": 62.0,
            "std_disk": 1.2,
            "base_lat": 20.0,
            "std_lat": 3.2,
            "anomalies": [
                (50, 61, "disk_pressure"),         # 12 log rotation failure / disk full
                (110, 121, "memory_spike"),        # 12 buffer cache bloat
                (170, 179, "latency_spike"),       # 10 database lock / connection pool queue
                (220, 234, "resource_contention"), # 15 simultaneous report queries
                (275, 285, "gradual_degradation"), # 11 progressive memory leak & latency climb
            ]
        },
        "hospital_server_03": {
            "role": "Radiology Picture Archiving & Communication System (PACS)",
            "base_cpu": 28.0,
            "std_cpu": 4.8,
            "base_mem": 58.0,
            "std_mem": 4.0,
            "base_disk": 76.0,
            "std_disk": 1.5,
            "base_lat": 18.0,
            "std_lat": 2.8,
            "anomalies": [
                (35, 46, "cpu_spike"),             # 12 3D volumetric image rendering
                (90, 101, "disk_pressure"),        # 12 high-resolution DICOM batch ingestion
                (150, 159, "latency_spike"),       # 10 DICOM transfer queue stall
                (205, 219, "resource_contention"), # 15 PACS ingest + multi-client retrieval
                (260, 270, "gradual_degradation"), # 11 progressive disk & latency exhaustion
            ]
        }
    }

    fieldnames = [
        "timestamp_utc",
        "server_id",
        "cpu_usage",
        "memory_usage",
        "disk_usage",
        "latency_ms",
        "is_anomaly",
        "anomaly_type",
    ]

    all_rows = []
    stats = {
        "total_records": 0,
        "servers": {},
        "normal_count": 0,
        "anomaly_count": 0,
        "anomaly_type_counts": {
            "normal": 0,
            "cpu_spike": 0,
            "memory_spike": 0,
            "disk_pressure": 0,
            "latency_spike": 0,
            "resource_contention": 0,
            "gradual_degradation": 0,
        }
    }

    for server_id, cfg in server_profiles.items():
        stats["servers"][server_id] = {"total": 0, "normal": 0, "anomaly": 0}
        
        # Build index-to-anomaly map
        anomaly_map = {}
        for start_idx, end_idx, atype in cfg["anomalies"]:
            for i in range(start_idx, end_idx + 1):
                anomaly_map[i] = (atype, start_idx, end_idx)

        # Generate 300 sequential observations
        for i in range(records_per_server):
            curr_time = start_time + timedelta(minutes=i * step_minutes)
            iso_time = curr_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            # Baseline normal metrics with realistic random Gaussian noise
            cpu = random.gauss(cfg["base_cpu"], cfg["std_cpu"])
            mem = random.gauss(cfg["base_mem"], cfg["std_mem"])
            disk = random.gauss(cfg["base_disk"], cfg["std_disk"])
            lat = random.gauss(cfg["base_lat"], cfg["std_lat"])

            # Add subtle diurnal fluctuation
            diurnal = 2.0 * random.uniform(-1.0, 1.0)
            cpu += diurnal
            mem += diurnal * 0.5

            if i in anomaly_map:
                atype, a_start, a_end = anomaly_map[i]
                is_anomaly = 1
                anomaly_type = atype

                if atype == "cpu_spike":
                    cpu = random.uniform(88.0, 97.5)
                    lat += random.uniform(5.0, 15.0)

                elif atype == "memory_spike":
                    mem = random.uniform(89.0, 98.2)
                    lat += random.uniform(8.0, 20.0)

                elif atype == "disk_pressure":
                    disk = random.uniform(92.0, 98.8)
                    lat += random.uniform(10.0, 25.0)

                elif atype == "latency_spike":
                    lat = random.uniform(150.0, 480.0)
                    cpu += random.uniform(3.0, 8.0)

                elif atype == "resource_contention":
                    cpu = random.uniform(88.0, 96.5)
                    mem = random.uniform(86.0, 94.5)
                    lat = random.uniform(220.0, 520.0)
                    disk += random.uniform(4.0, 8.0)

                elif atype == "gradual_degradation":
                    # Progression factor from 0.0 to 1.0 across the degradation window
                    span = max(1, a_end - a_start)
                    progress = (i - a_start) / span
                    cpu += progress * 48.0
                    mem += progress * 32.0
                    lat += progress * 160.0
                    if server_id == "hospital_server_03":
                        disk += progress * 20.0
            else:
                is_anomaly = 0
                anomaly_type = "normal"

            # Enforce physical and operational bounds
            cpu = max(0.5, min(99.9, cpu))
            mem = max(1.0, min(99.9, mem))
            disk = max(1.0, min(99.9, disk))
            lat = max(1.0, lat)

            row = {
                "timestamp_utc": iso_time,
                "server_id": server_id,
                "cpu_usage": round(cpu, 2),
                "memory_usage": round(mem, 2),
                "disk_usage": round(disk, 2),
                "latency_ms": round(lat, 2),
                "is_anomaly": is_anomaly,
                "anomaly_type": anomaly_type,
            }
            all_rows.append(row)

            # Update stats
            stats["total_records"] += 1
            stats["servers"][server_id]["total"] += 1
            if is_anomaly:
                stats["anomaly_count"] += 1
                stats["servers"][server_id]["anomaly"] += 1
            else:
                stats["normal_count"] += 1
                stats["servers"][server_id]["normal"] += 1
            stats["anomaly_type_counts"][anomaly_type] += 1

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Write CSV
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    file_size_bytes = os.path.getsize(output_path)
    stats["file_size_bytes"] = file_size_bytes
    stats["file_size_kb"] = round(file_size_bytes / 1024, 2)
    stats["first_5_records"] = all_rows[:5]

    return stats


if __name__ == "__main__":
    results = generate_dataset()
    print("=" * 60)
    print("DATACAT TELEMETRY SYNTHETIC DATASET GENERATION COMPLETE")
    print("=" * 60)
    print(f"Total Records:         {results['total_records']}")
    print(f"Normal Records (0):    {results['normal_count']} ({results['normal_count']/results['total_records']*100:.1f}%)")
    print(f"Anomaly Records (1):   {results['anomaly_count']} ({results['anomaly_count']/results['total_records']*100:.1f}%)")
    print(f"Output File Size:      {results['file_size_bytes']} bytes ({results['file_size_kb']} KB)")
    print("\nRecords per Server:")
    for s_id, s_stats in results["servers"].items():
        print(f"  - {s_id}: Total={s_stats['total']}, Normal={s_stats['normal']}, Anomaly={s_stats['anomaly']}")
    print("\nAnomaly Type Breakdown:")
    for a_type, count in results["anomaly_type_counts"].items():
        print(f"  - {a_type:<22}: {count:>4} ({count/results['total_records']*100:.1f}%)")
    print("\nFirst 5 Records:")
    for r in results["first_5_records"]:
        print(" ", r)
    print("=" * 60)
