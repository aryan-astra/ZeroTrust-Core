"""
ZeroTrust - AMD Performance Benchmarking Suite
Measures inference latency, throughput, and CPU utilization under varying
thread counts and batch sizes.  Designed for AMD EPYC / Ryzen / Threadripper
architectures but runs on any x86-64 platform.

Usage:
    python benchmark.py                     # Full benchmark
    python benchmark.py --quick             # Quick run (smaller batches)
    python benchmark.py --output results    # Save JSON + CSV to results/
"""

import os
import sys
import json
import time
import math
import platform
import argparse
import statistics
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import settings
from ml.inference import (
    load_models, predict_network_anomaly, predict_phishing,
    batch_predict_network, batch_predict_phishing, get_feature_columns,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def get_cpu_info() -> dict:
    """Collect CPU metadata."""
    info = {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "physical_cores": os.cpu_count(),
    }
    try:
        import subprocess
        result = subprocess.run(
            ["wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed", "/format:list"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if "=" in line:
                key, val = line.split("=", 1)
                info[key.strip()] = val.strip()
    except Exception:
        pass
    return info


def generate_network_sample(features: list) -> dict:
    """Generate a realistic random network feature vector."""
    sample = {}
    for feat in features:
        if "duration" in feat.lower():
            sample[feat] = float(np.random.exponential(5000))
        elif "packet" in feat.lower() or "count" in feat.lower():
            sample[feat] = float(np.random.poisson(10))
        elif "byte" in feat.lower() or "length" in feat.lower():
            sample[feat] = float(np.random.exponential(500))
        elif "rate" in feat.lower() or "ratio" in feat.lower():
            sample[feat] = float(np.random.uniform(0, 1))
        else:
            sample[feat] = float(np.random.normal(0, 1))
    return sample


PHISHING_SAMPLES = [
    "URGENT: Your account has been compromised! Click here immediately http://evil.tk/hack to verify your identity",
    "Dear user, we detected suspicious activity. Verify your credentials at http://192.168.1.1/login",
    "Hi team, the quarterly report is ready for review. Please check the shared drive. Best, Sarah",
    "Meeting rescheduled to 3 PM tomorrow. Conference room B.",
    "CONGRATULATIONS! You won $1,000,000!!! Claim now http://scam.xyz/claim?id=12345 ACT NOW!!!",
    "Your package from Amazon is delayed. Track here: http://amaz0n-tracking.ru/pkg",
    "Monthly infrastructure review: all systems nominal. Uptime 99.97%.",
    "Password reset requested for admin@company.com. If this was not you, click: http://ph1sh.net/reset",
]


def run_latency_benchmark(n_samples: int, features: list) -> dict:
    """Benchmark single-sample latency (sequential)."""
    print(f"\n  Single-sample latency ({n_samples} iterations)...")

    # Network
    net_latencies = []
    for _ in range(n_samples):
        sample = generate_network_sample(features)
        t0 = time.perf_counter()
        predict_network_anomaly(sample)
        net_latencies.append((time.perf_counter() - t0) * 1000)

    # Phishing
    phi_latencies = []
    for _ in range(n_samples):
        text = PHISHING_SAMPLES[np.random.randint(0, len(PHISHING_SAMPLES))]
        t0 = time.perf_counter()
        predict_phishing(text)
        phi_latencies.append((time.perf_counter() - t0) * 1000)

    return {
        "network": {
            "samples": n_samples,
            "mean_ms": round(statistics.mean(net_latencies), 3),
            "median_ms": round(statistics.median(net_latencies), 3),
            "p95_ms": round(sorted(net_latencies)[int(n_samples * 0.95)], 3),
            "p99_ms": round(sorted(net_latencies)[int(n_samples * 0.99)], 3),
            "min_ms": round(min(net_latencies), 3),
            "max_ms": round(max(net_latencies), 3),
            "std_ms": round(statistics.stdev(net_latencies), 3) if n_samples > 1 else 0,
        },
        "phishing": {
            "samples": n_samples,
            "mean_ms": round(statistics.mean(phi_latencies), 3),
            "median_ms": round(statistics.median(phi_latencies), 3),
            "p95_ms": round(sorted(phi_latencies)[int(n_samples * 0.95)], 3),
            "p99_ms": round(sorted(phi_latencies)[int(n_samples * 0.99)], 3),
            "min_ms": round(min(phi_latencies), 3),
            "max_ms": round(max(phi_latencies), 3),
            "std_ms": round(statistics.stdev(phi_latencies), 3) if n_samples > 1 else 0,
        },
    }


def run_throughput_benchmark(batch_sizes: list, thread_counts: list, features: list) -> dict:
    """Benchmark batch throughput across different thread counts."""
    print(f"\n  Batch throughput (batch_sizes={batch_sizes}, threads={thread_counts})...")
    results = {}

    for batch_size in batch_sizes:
        net_samples = [generate_network_sample(features) for _ in range(batch_size)]
        phi_samples = [PHISHING_SAMPLES[i % len(PHISHING_SAMPLES)] for i in range(batch_size)]

        results[f"batch_{batch_size}"] = {}

        for n_threads in thread_counts:
            label = f"{n_threads}T"
            print(f"    batch={batch_size}, threads={n_threads}...", end=" ", flush=True)

            # Network batch
            t0 = time.perf_counter()
            batch_predict_network(net_samples, max_workers=n_threads)
            net_elapsed = time.perf_counter() - t0
            net_throughput = batch_size / net_elapsed

            # Phishing batch
            t0 = time.perf_counter()
            batch_predict_phishing(phi_samples, max_workers=n_threads)
            phi_elapsed = time.perf_counter() - t0
            phi_throughput = batch_size / phi_elapsed

            results[f"batch_{batch_size}"][label] = {
                "threads": n_threads,
                "network_elapsed_s": round(net_elapsed, 3),
                "network_throughput_per_s": round(net_throughput, 1),
                "phishing_elapsed_s": round(phi_elapsed, 3),
                "phishing_throughput_per_s": round(phi_throughput, 1),
            }
            print(f"net={net_throughput:.0f}/s, phi={phi_throughput:.0f}/s")

    return results


def run_scaling_benchmark(features: list, max_threads: int = None) -> dict:
    """Measure throughput scaling across 1 to max_threads."""
    max_t = max_threads or min(os.cpu_count() or 4, 16)
    thread_range = [1]
    t = 2
    while t <= max_t:
        thread_range.append(t)
        t *= 2
    if max_t not in thread_range:
        thread_range.append(max_t)

    batch_size = 200
    net_samples = [generate_network_sample(features) for _ in range(batch_size)]
    phi_samples = [PHISHING_SAMPLES[i % len(PHISHING_SAMPLES)] for i in range(batch_size)]

    print(f"\n  Thread scaling (batch={batch_size}, threads={thread_range})...")
    results = []

    baseline_net = None
    baseline_phi = None

    for n_threads in thread_range:
        # Network
        t0 = time.perf_counter()
        batch_predict_network(net_samples, max_workers=n_threads)
        net_elapsed = time.perf_counter() - t0
        net_tp = batch_size / net_elapsed

        # Phishing
        t0 = time.perf_counter()
        batch_predict_phishing(phi_samples, max_workers=n_threads)
        phi_elapsed = time.perf_counter() - t0
        phi_tp = batch_size / phi_elapsed

        if baseline_net is None:
            baseline_net = net_tp
            baseline_phi = phi_tp

        entry = {
            "threads": n_threads,
            "network_throughput_per_s": round(net_tp, 1),
            "network_speedup": round(net_tp / baseline_net, 2),
            "phishing_throughput_per_s": round(phi_tp, 1),
            "phishing_speedup": round(phi_tp / baseline_phi, 2),
        }
        results.append(entry)
        print(f"    {n_threads}T: net={net_tp:.0f}/s ({entry['network_speedup']:.2f}x), "
              f"phi={phi_tp:.0f}/s ({entry['phishing_speedup']:.2f}x)")

    return {"batch_size": batch_size, "scaling": results}


def print_summary(report: dict):
    """Print human-readable benchmark summary."""
    print("\n" + "=" * 70)
    print("  BENCHMARK SUMMARY")
    print("=" * 70)

    cpu = report.get("cpu_info", {})
    print(f"\n  Platform:   {cpu.get('platform', 'N/A')}")
    print(f"  Processor:  {cpu.get('Name', cpu.get('processor', 'N/A'))}")
    print(f"  Cores:      {cpu.get('NumberOfCores', cpu.get('physical_cores', 'N/A'))}")
    print(f"  Threads:    {cpu.get('NumberOfLogicalProcessors', 'N/A')}")

    lat = report.get("latency", {})
    net = lat.get("network", {})
    phi = lat.get("phishing", {})
    print(f"\n  --- Single-Sample Latency ---")
    print(f"  Network:  mean={net.get('mean_ms', 'N/A')}ms  p95={net.get('p95_ms', 'N/A')}ms  p99={net.get('p99_ms', 'N/A')}ms")
    print(f"  Phishing: mean={phi.get('mean_ms', 'N/A')}ms  p95={phi.get('p95_ms', 'N/A')}ms  p99={phi.get('p99_ms', 'N/A')}ms")

    scaling = report.get("scaling", {}).get("scaling", [])
    if scaling:
        print(f"\n  --- Thread Scaling ---")
        for s in scaling:
            print(f"  {s['threads']:>2}T: net={s['network_throughput_per_s']:>8.1f}/s ({s['network_speedup']:.2f}x)  "
                  f"phi={s['phishing_throughput_per_s']:>8.1f}/s ({s['phishing_speedup']:.2f}x)")

    print(f"\n  Total benchmark time: {report.get('total_time_s', 'N/A')}s")
    print("=" * 70)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ZeroTrust AMD Performance Benchmark")
    parser.add_argument("--quick", action="store_true", help="Quick benchmark with smaller workloads")
    parser.add_argument("--output", type=str, default="benchmark_results", help="Output directory")
    args = parser.parse_args()

    print("=" * 70)
    print("  ZeroTrust - AMD Performance Benchmark")
    print("=" * 70)

    t_total = time.perf_counter()

    # CPU info
    print("\n[1/5] Collecting CPU info...")
    cpu_info = get_cpu_info()

    # Load models
    print("\n[2/5] Loading models...")
    load_models()
    features = get_feature_columns()
    if not features:
        print("[!] No model features found. Train models first: python train_all.py")
        sys.exit(1)

    # Warmup
    print("\n[3/5] Warmup (5 iterations)...")
    for _ in range(5):
        predict_network_anomaly(generate_network_sample(features))
        predict_phishing(PHISHING_SAMPLES[0])

    # Latency benchmark
    n_latency = 50 if args.quick else 200
    print(f"\n[4/5] Latency benchmark ({n_latency} samples)...")
    latency = run_latency_benchmark(n_latency, features)

    # Throughput + scaling
    if args.quick:
        batch_sizes = [50, 100]
        thread_counts = [1, 2, 4]
    else:
        batch_sizes = [50, 100, 500]
        thread_counts = [1, 2, 4, 8]

    print(f"\n[5/5] Throughput & scaling benchmark...")
    throughput = run_throughput_benchmark(batch_sizes, thread_counts, features)
    scaling = run_scaling_benchmark(features)

    total_time = round(time.perf_counter() - t_total, 2)

    # Build report
    report = {
        "benchmark_version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "cpu_info": cpu_info,
        "model_features": len(features),
        "latency": latency,
        "throughput": throughput,
        "scaling": scaling,
        "total_time_s": total_time,
    }

    # Save results
    os.makedirs(args.output, exist_ok=True)
    json_path = os.path.join(args.output, "benchmark.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Results saved: {json_path}")

    # CSV summary
    csv_path = os.path.join(args.output, "scaling_summary.csv")
    with open(csv_path, "w") as f:
        f.write("threads,net_throughput_per_s,net_speedup,phi_throughput_per_s,phi_speedup\n")
        for s in scaling.get("scaling", []):
            f.write(f"{s['threads']},{s['network_throughput_per_s']},{s['network_speedup']},"
                    f"{s['phishing_throughput_per_s']},{s['phishing_speedup']}\n")
    print(f"  Scaling CSV: {csv_path}")

    # Print summary
    print_summary(report)


if __name__ == "__main__":
    main()
