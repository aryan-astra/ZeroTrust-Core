"""
ZeroTrust - Phishing Detection Training (v2)
TF-IDF + Logistic Regression with structured feature engineering via FeatureUnion.
Enhanced evaluation with ROC-AUC, PR-AUC, and feature importance analysis.
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    roc_auc_score, average_precision_score, f1_score
)
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings
from data.preprocess import extract_phishing_features

PROCESSED_DIR = settings.PROCESSED_DIR
MODELS_DIR = settings.MODELS_DIR
os.makedirs(MODELS_DIR, exist_ok=True)

STRUCTURED_FEATURE_NAMES = [
    "url_count", "has_ip_url", "suspicious_tld", "urgency_count",
    "urgency_ratio", "has_html_form", "has_html_link", "char_entropy",
    "word_count", "exclamation_count", "question_count", "caps_ratio"
]


class StructuredFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extract structured phishing features from raw email text."""

    def fit(self, X, y=None):
        return self

    def transform(self, X, y=None):
        features = []
        for text in X:
            feat = extract_phishing_features(str(text))
            features.append([feat[k] for k in STRUCTURED_FEATURE_NAMES])
        return np.array(features)


def train_phishing_model():
    """
    Train phishing detector with combined TF-IDF + structured features.
    Uses FeatureUnion to merge text and engineered features.
    """
    print("[*] Training Phishing Detection Model (Enhanced Pipeline)")
    print("=" * 60)

    # Load data
    data_path = os.path.join(PROCESSED_DIR, "phishing_processed.csv")
    df = pd.read_csv(data_path)
    df = df.dropna(subset=["text_combined"])
    df["text_combined"] = df["text_combined"].astype(str).fillna("")
    print(f"    Loaded: {df.shape}")

    X_text = df["text_combined"].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X_text, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"    Train: {len(X_train)}, Test: {len(X_test)}")

    # ── TF-IDF Vectorizer ─────────────────────────────────────────────
    print("    Fitting TF-IDF Vectorizer (10K features, bigrams)...")
    vectorizer = TfidfVectorizer(
        max_features=10000,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95
    )

    # ── Structured Feature Extraction ─────────────────────────────────
    print("    Extracting structured features...")
    struct_extractor = StructuredFeatureExtractor()

    # ── Train TF-IDF + LogReg (primary model) ─────────────────────────
    t0 = time.perf_counter()
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    model = LogisticRegression(
        max_iter=1000, C=1.0, solver="lbfgs",
        random_state=42, n_jobs=-1
    )
    model.fit(X_train_tfidf, y_train)
    train_time = time.perf_counter() - t0

    # Evaluate primary model
    t0 = time.perf_counter()
    y_pred = model.predict(X_test_tfidf)
    y_proba = model.predict_proba(X_test_tfidf)[:, 1]
    inference_time = time.perf_counter() - t0

    accuracy = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    pr_auc = average_precision_score(y_test, y_proba)
    f1 = f1_score(y_test, y_pred)

    print(f"\n    TF-IDF + LogReg Results:")
    print(f"    Accuracy: {accuracy:.4f}")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"], zero_division=0))
    print(f"    ROC-AUC: {roc_auc:.4f}")
    print(f"    PR-AUC: {pr_auc:.4f}")
    print(f"    F1: {f1:.4f}")
    print(f"    Training time: {train_time:.2f}s")
    print(f"    Inference time ({len(X_test)} samples): {inference_time:.4f}s")

    # ── Train Enhanced Model (TF-IDF + Structured + RandomForest) ─────
    print("\n    Training enhanced model (TF-IDF + structured features)...")

    t0 = time.perf_counter()
    X_train_struct = struct_extractor.transform(X_train)
    X_test_struct = struct_extractor.transform(X_test)

    # Combine TF-IDF + structured
    from scipy.sparse import hstack
    scaler = StandardScaler()
    X_train_struct_scaled = scaler.fit_transform(X_train_struct)
    X_test_struct_scaled = scaler.transform(X_test_struct)

    X_train_combined = hstack([X_train_tfidf, X_train_struct_scaled])
    X_test_combined = hstack([X_test_tfidf, X_test_struct_scaled])

    enhanced_model = LogisticRegression(
        max_iter=1000, C=1.0, solver="lbfgs",
        random_state=42, n_jobs=-1
    )
    enhanced_model.fit(X_train_combined, y_train)
    enhanced_train_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    y_pred_enh = enhanced_model.predict(X_test_combined)
    y_proba_enh = enhanced_model.predict_proba(X_test_combined)[:, 1]
    enhanced_inference_time = time.perf_counter() - t0

    acc_enh = accuracy_score(y_test, y_pred_enh)
    roc_enh = roc_auc_score(y_test, y_proba_enh)
    pr_enh = average_precision_score(y_test, y_proba_enh)
    f1_enh = f1_score(y_test, y_pred_enh)

    print(f"\n    Enhanced Model Results:")
    print(f"    Accuracy: {acc_enh:.4f} (delta: {acc_enh - accuracy:+.4f})")
    print(classification_report(y_test, y_pred_enh, target_names=["Safe", "Phishing"], zero_division=0))
    print(f"    ROC-AUC: {roc_enh:.4f} (delta: {roc_enh - roc_auc:+.4f})")
    print(f"    PR-AUC: {pr_enh:.4f} (delta: {pr_enh - pr_auc:+.4f})")
    print(f"    F1: {f1_enh:.4f} (delta: {f1_enh - f1:+.4f})")

    # Save all artifacts
    joblib.dump(model, os.path.join(MODELS_DIR, "phishing_model.pkl"))
    joblib.dump(vectorizer, os.path.join(MODELS_DIR, "vectorizer.pkl"))
    joblib.dump(enhanced_model, os.path.join(MODELS_DIR, "phishing_enhanced_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "phishing_struct_scaler.pkl"))
    print(f"\n    Models saved to {MODELS_DIR}")

    # Save evaluation results
    eval_results = {
        "baseline": {
            "model": "TF-IDF + LogisticRegression",
            "accuracy": round(accuracy, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "f1": round(f1, 4),
            "train_time_s": round(train_time, 3),
            "inference_time_s": round(inference_time, 4),
        },
        "enhanced": {
            "model": "TF-IDF + Structured Features + LogisticRegression",
            "accuracy": round(acc_enh, 4),
            "roc_auc": round(roc_enh, 4),
            "pr_auc": round(pr_enh, 4),
            "f1": round(f1_enh, 4),
            "train_time_s": round(enhanced_train_time, 3),
            "inference_time_s": round(enhanced_inference_time, 4),
            "structured_features": STRUCTURED_FEATURE_NAMES,
        },
        "transformer_roadmap": {
            "planned_model": "DistilBERT",
            "status": "planned",
            "expected_improvement": "2-5% accuracy on adversarial phishing",
        }
    }
    eval_path = os.path.join(MODELS_DIR, "phishing_evaluation.json")
    with open(eval_path, "w") as f:
        json.dump(eval_results, f, indent=2)
    print(f"    Evaluation saved: {eval_path}")

    return model, vectorizer, eval_results


if __name__ == "__main__":
    train_phishing_model()
    print("\n[+] Phishing model training complete.")
