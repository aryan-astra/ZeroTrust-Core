"""
ZeroTrust - Network Anomaly Detection Training (v2)
Hybrid detection: Isolation Forest (unsupervised) + RandomForest (supervised).
Includes contamination tuning, threshold calibration, full evaluation metrics,
and benchmark logging.
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    roc_auc_score, average_precision_score, f1_score, roc_curve
)
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

PROCESSED_DIR = settings.PROCESSED_DIR
MODELS_DIR = settings.MODELS_DIR
os.makedirs(MODELS_DIR, exist_ok=True)


def tune_contamination(X_normal, X_eval, y_eval, feature_cols):
    """Grid search over contamination values using ROC-AUC."""
    print("    Tuning contamination parameter...")
    best_auc = 0
    best_c = 0.05
    results = []

    for c in [0.01, 0.02, 0.03, 0.05, 0.07, 0.1]:
        model = IsolationForest(
            n_estimators=100, contamination=c,
            random_state=42, n_jobs=-1, verbose=0
        )
        model.fit(X_normal)
        scores = -model.decision_function(X_eval)  # higher = more anomalous
        try:
            auc = roc_auc_score(y_eval, scores)
        except ValueError:
            auc = 0.5
        results.append({"contamination": c, "roc_auc": round(auc, 4)})
        if auc > best_auc:
            best_auc = auc
            best_c = c

    print(f"    Contamination tuning results:")
    for r in results:
        marker = " <-- best" if r["contamination"] == best_c else ""
        print(f"      c={r['contamination']:.2f} -> ROC-AUC={r['roc_auc']:.4f}{marker}")

    return best_c, results


def train_isolation_forest(X_normal, X_eval, y_eval, contamination=None):
    """Train Isolation Forest on normal-only data, evaluate on mixed."""
    print("\n[*] Training Isolation Forest (normal-only training)...")

    if contamination is None:
        contamination, _ = tune_contamination(
            X_normal, X_eval, y_eval, None
        )

    t0 = time.perf_counter()
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    model.fit(X_normal)
    train_time = time.perf_counter() - t0
    print(f"    Training time: {train_time:.2f}s (contamination={contamination})")

    # Evaluate on mixed data
    t0 = time.perf_counter()
    y_pred_raw = model.predict(X_eval)
    inference_time = time.perf_counter() - t0

    y_pred = np.where(y_pred_raw == -1, 1, 0)
    scores = -model.decision_function(X_eval)

    # Threshold calibration
    percentiles = np.percentile(scores, [90, 95, 99])
    print(f"    Score percentiles: 90th={percentiles[0]:.4f}, 95th={percentiles[1]:.4f}, 99th={percentiles[2]:.4f}")

    # Metrics
    print(f"\n    Isolation Forest Evaluation:")
    print(classification_report(y_eval, y_pred, target_names=["Normal", "Anomaly"], zero_division=0))

    try:
        roc_auc = roc_auc_score(y_eval, scores)
        pr_auc = average_precision_score(y_eval, scores)
        f1 = f1_score(y_eval, y_pred)
    except ValueError:
        roc_auc = pr_auc = f1 = 0.0

    cm = confusion_matrix(y_eval, y_pred)
    print(f"    Confusion Matrix:\n    {cm}")
    print(f"    ROC-AUC: {roc_auc:.4f}")
    print(f"    PR-AUC: {pr_auc:.4f}")
    print(f"    F1 (anomaly): {f1:.4f}")
    print(f"    Inference time ({len(X_eval)} samples): {inference_time:.4f}s")

    # Save
    model_path = os.path.join(MODELS_DIR, "network_model.pkl")
    joblib.dump(model, model_path)
    print(f"    Model saved: {model_path}")

    metrics = {
        "model": "IsolationForest",
        "contamination": contamination,
        "n_estimators": 200,
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "f1_anomaly": round(f1, 4),
        "train_time_s": round(train_time, 3),
        "inference_time_s": round(inference_time, 4),
        "threshold_p95": round(float(percentiles[1]), 4),
    }

    return model, metrics


def train_supervised_classifier(X_train, y_train, X_test, y_test):
    """Train RandomForest supervised classifier on labeled attack data."""
    print("\n[*] Training Supervised Classifier (RandomForest)...")

    t0 = time.perf_counter()
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    inference_time = time.perf_counter() - t0

    accuracy = accuracy_score(y_test, y_pred)
    try:
        roc_auc = roc_auc_score(y_test, y_proba)
        pr_auc = average_precision_score(y_test, y_proba)
        f1 = f1_score(y_test, y_pred)
    except ValueError:
        roc_auc = pr_auc = f1 = 0.0

    print(f"\n    Supervised Classifier Evaluation:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"], zero_division=0))
    print(f"    Accuracy: {accuracy:.4f}")
    print(f"    ROC-AUC: {roc_auc:.4f}")
    print(f"    PR-AUC: {pr_auc:.4f}")
    print(f"    F1: {f1:.4f}")
    print(f"    Training time: {train_time:.2f}s")
    print(f"    Inference time ({len(X_test)} samples): {inference_time:.4f}s")

    model_path = os.path.join(MODELS_DIR, "supervised_network_model.pkl")
    joblib.dump(clf, model_path)
    print(f"    Model saved: {model_path}")

    metrics = {
        "model": "RandomForestClassifier",
        "n_estimators": 200,
        "accuracy": round(accuracy, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "f1": round(f1, 4),
        "train_time_s": round(train_time, 3),
        "inference_time_s": round(inference_time, 4),
    }

    return clf, metrics


def train_network_models():
    """Full hybrid network training pipeline."""
    print("[*] Training Network Anomaly Detection (Hybrid Pipeline)")
    print("=" * 60)

    # Load normal-only data for IF
    normal_path = os.path.join(PROCESSED_DIR, "network_normal_only.csv")
    mixed_path = os.path.join(PROCESSED_DIR, "network_mixed.csv")

    normal_df = pd.read_csv(normal_path)
    mixed_df = pd.read_csv(mixed_path)

    feature_cols = [c for c in normal_df.columns if c not in ["label", "attack_class", "attack_type"]]
    X_normal = normal_df[feature_cols].values

    X_mixed = mixed_df[feature_cols].values
    y_mixed = mixed_df["label"].values

    # Train/test split for evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X_mixed, y_mixed, test_size=0.2, random_state=42, stratify=y_mixed
    )

    # Train Isolation Forest (on normal-only, evaluate on mixed test)
    if_model, if_metrics = train_isolation_forest(X_normal, X_test, y_test)

    # Train supervised classifier (on labeled mixed data)
    sup_model, sup_metrics = train_supervised_classifier(X_train, y_train, X_test, y_test)

    # Save evaluation results
    eval_results = {
        "isolation_forest": if_metrics,
        "supervised_classifier": sup_metrics,
        "hybrid_weights": {"isolation_forest": 0.4, "supervised": 0.6},
    }
    eval_path = os.path.join(MODELS_DIR, "network_evaluation.json")
    with open(eval_path, "w") as f:
        json.dump(eval_results, f, indent=2)
    print(f"\n    Evaluation results saved: {eval_path}")

    return if_model, sup_model, eval_results


if __name__ == "__main__":
    train_network_models()
    print("\n[+] Network model training complete.")
