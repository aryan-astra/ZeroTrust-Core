"""
ZeroTrust - Training Orchestrator (v2)
Runs full pipeline: preprocessing -> network training -> phishing training.
"""

import os
import sys
import time
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import settings

def run_pipeline(skip_preprocess=False, skip_network=False, skip_phishing=False):
    """Execute the complete training pipeline."""
    results = {}
    total_start = time.time()

    os.makedirs(settings.MODELS_DIR, exist_ok=True)
    os.makedirs(settings.PROCESSED_DIR, exist_ok=True)

    # Phase 1: Preprocessing
    if not skip_preprocess:
        print("=" * 60)
        print("PHASE 1: DATA PREPROCESSING")
        print("=" * 60)
        from data.preprocess import preprocess_network_data, preprocess_phishing_data

        t0 = time.time()
        net_info = preprocess_network_data()
        results["network_preprocessing"] = {
            "status": "success" if net_info is not None else "skipped",
            "duration_s": round(time.time() - t0, 2),
        }
        print()

        t0 = time.time()
        phi_info = preprocess_phishing_data()
        results["phishing_preprocessing"] = {
            "status": "success" if phi_info is not None else "skipped",
            "duration_s": round(time.time() - t0, 2),
        }
        print()
    else:
        print("[*] Skipping preprocessing\n")

    # Phase 2: Network model training
    if not skip_network:
        print("=" * 60)
        print("PHASE 2: NETWORK ANOMALY DETECTION")
        print("=" * 60)
        from ml.train_network import train_network_models

        t0 = time.time()
        net_result = train_network_models()
        results["network_training"] = {
            "status": "success" if net_result else "failed",
            "duration_s": round(time.time() - t0, 2),
        }
        print()
    else:
        print("[*] Skipping network training\n")

    # Phase 3: Phishing model training
    if not skip_phishing:
        print("=" * 60)
        print("PHASE 3: PHISHING DETECTION")
        print("=" * 60)
        from ml.train_phishing import train_phishing_model

        t0 = time.time()
        phi_result = train_phishing_model()
        results["phishing_training"] = {
            "status": "success" if phi_result else "failed",
            "duration_s": round(time.time() - t0, 2),
        }
        print()
    else:
        print("[*] Skipping phishing training\n")

    # Summary
    total_duration = round(time.time() - total_start, 2)
    results["total_duration_s"] = total_duration

    print("=" * 60)
    print(f"PIPELINE COMPLETE — {total_duration}s total")
    print("=" * 60)
    for k, v in results.items():
        if isinstance(v, dict):
            print(f"  {k}: {v.get('status', 'N/A')} ({v.get('duration_s', '?')}s)")
    print()

    # Save summary
    summary_path = os.path.join(settings.MODELS_DIR, "training_summary.json")
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[+] Summary saved to {summary_path}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroTrust Training Pipeline v2")
    parser.add_argument("--skip-preprocess", action="store_true")
    parser.add_argument("--skip-network", action="store_true")
    parser.add_argument("--skip-phishing", action="store_true")
    args = parser.parse_args()

    run_pipeline(
        skip_preprocess=args.skip_preprocess,
        skip_network=args.skip_network,
        skip_phishing=args.skip_phishing,
    )
