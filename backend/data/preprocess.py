"""
ZeroTrust - Data Preprocessing Module (v2)
Enhanced cleaning, normalization, and feature engineering for both datasets.
Supports normal-only training split for Isolation Forest.
"""

import os
import sys
import re
import math
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

PROCESSED_DIR = settings.PROCESSED_DIR
DATASETS_DIR = settings.DATASETS_DIR
os.makedirs(PROCESSED_DIR, exist_ok=True)


def preprocess_network_data(sample_size=100000):
    """
    Preprocess CICIDS2017 network data.
    Creates TWO splits:
      1. normal_only - for Isolation Forest training (unsupervised, normal traffic only)
      2. mixed - for supervised classifier training + evaluation
    """
    print("[*] Loading CICIDS2017 network traffic dataset...")
    raw_path = os.path.join(DATASETS_DIR, "cicids2017_cleaned.csv")
    df = pd.read_csv(raw_path)
    print(f"    Raw shape: {df.shape}")

    label_col = "Attack Type"
    feature_cols = [c for c in df.columns if c != label_col]

    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    print(f"    After cleaning: {df.shape}")

    # Encode attack types
    attack_types = df[label_col].unique()
    print(f"    Attack types: {list(attack_types)}")

    # Binary label
    df["label"] = (df[label_col] != "Normal Traffic").astype(int)

    # Multi-class label for supervised
    attack_map = {t: i for i, t in enumerate(sorted(df[label_col].unique()))}
    df["attack_class"] = df[label_col].map(attack_map)

    normal_count = len(df[df["label"] == 0])
    attack_count = len(df[df["label"] == 1])
    print(f"    Normal: {normal_count}, Attack: {attack_count}")

    # ── Split 1: Normal-only for Isolation Forest ──────────────────────
    normal_df = df[df["label"] == 0]
    if len(normal_df) > int(sample_size * 0.7):
        normal_sample = normal_df.sample(n=int(sample_size * 0.7), random_state=42)
    else:
        normal_sample = normal_df

    X_normal = normal_sample[feature_cols].values
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)

    normal_out = pd.DataFrame(X_normal_scaled, columns=feature_cols)
    normal_out["label"] = 0
    normal_path = os.path.join(PROCESSED_DIR, "network_normal_only.csv")
    normal_out.to_csv(normal_path, index=False)
    print(f"    Saved normal-only data: {normal_out.shape} -> {normal_path}")

    # ── Split 2: Mixed stratified for supervised + evaluation ──────────
    attack_sample_n = min(int(sample_size * 0.3), attack_count)
    normal_sample_n = min(int(sample_size * 0.7), normal_count)
    normal_mix = df[df["label"] == 0].sample(n=normal_sample_n, random_state=42)
    attack_mix = df[df["label"] == 1].sample(n=attack_sample_n, random_state=42)
    mixed = pd.concat([normal_mix, attack_mix]).sample(frac=1, random_state=42).reset_index(drop=True)

    X_mixed = mixed[feature_cols].values
    X_mixed_scaled = scaler.transform(X_mixed)

    mixed_out = pd.DataFrame(X_mixed_scaled, columns=feature_cols)
    mixed_out["label"] = mixed["label"].values
    mixed_out["attack_class"] = mixed["attack_class"].values
    mixed_out["attack_type"] = mixed[label_col].values
    mixed_path = os.path.join(PROCESSED_DIR, "network_mixed.csv")
    mixed_out.to_csv(mixed_path, index=False)
    print(f"    Saved mixed data: {mixed_out.shape} -> {mixed_path}")

    # ── Also save the old combined for backward compat ─────────────────
    combined_path = os.path.join(PROCESSED_DIR, "network_processed.csv")
    mixed_out[feature_cols + ["label"]].to_csv(combined_path, index=False)

    # Save scaler and feature columns
    joblib.dump(scaler, os.path.join(PROCESSED_DIR, "network_scaler.pkl"))
    joblib.dump(feature_cols, os.path.join(PROCESSED_DIR, "network_feature_columns.pkl"))
    joblib.dump(attack_map, os.path.join(PROCESSED_DIR, "attack_type_map.pkl"))
    print(f"    Saved scaler, feature columns, attack map")

    return X_mixed_scaled, mixed["label"].values, feature_cols


# ─── Phishing Feature Engineering ─────────────────────────────────────────────

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc", ".buzz"}
URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspended", "verify", "confirm", "click here",
    "act now", "limited time", "expire", "account", "password", "compromised",
    "unauthorized", "security alert", "update your", "congratulations", "winner",
    "free", "prize", "selected", "won", "reward", "offer"
]


def extract_phishing_features(text: str) -> dict:
    """Extract structured features from email text beyond TF-IDF."""
    text_lower = text.lower() if text else ""

    # URL features
    urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text_lower)
    url_count = len(urls)
    has_ip_url = any(re.search(r'\d+\.\d+\.\d+\.\d+', u) for u in urls)
    suspicious_tld = any(any(u.endswith(tld) for tld in SUSPICIOUS_TLDS) for u in urls)

    # Urgency keywords
    urgency_count = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    urgency_ratio = urgency_count / max(len(text_lower.split()), 1)

    # HTML detection
    has_html_form = bool(re.search(r'<form|<input|<button', text_lower))
    has_html_link = bool(re.search(r'<a\s+href', text_lower))

    # Character entropy
    if text:
        char_counts = {}
        for ch in text:
            char_counts[ch] = char_counts.get(ch, 0) + 1
        total = len(text)
        entropy = -sum((c / total) * math.log2(c / total) for c in char_counts.values() if c > 0)
    else:
        entropy = 0.0

    # Text statistics
    word_count = len(text_lower.split())
    exclamation_count = text.count("!") if text else 0
    question_count = text.count("?") if text else 0
    caps_ratio = sum(1 for c in (text or "") if c.isupper()) / max(len(text or "x"), 1)

    return {
        "url_count": url_count,
        "has_ip_url": int(has_ip_url),
        "suspicious_tld": int(suspicious_tld),
        "urgency_count": urgency_count,
        "urgency_ratio": round(urgency_ratio, 4),
        "has_html_form": int(has_html_form),
        "has_html_link": int(has_html_link),
        "char_entropy": round(entropy, 4),
        "word_count": word_count,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "caps_ratio": round(caps_ratio, 4),
    }


def preprocess_phishing_data(sample_size=50000):
    """
    Preprocess phishing emails with enhanced feature engineering.
    Extracts structured features + saves cleaned text for TF-IDF.
    """
    print("\n[*] Loading phishing email dataset...")
    raw_path = os.path.join(DATASETS_DIR, "phishing_email.csv")
    df = pd.read_csv(raw_path)
    print(f"    Raw shape: {df.shape}")

    df.dropna(subset=["text_combined"], inplace=True)
    df["text_combined"] = df["text_combined"].astype(str).str.lower().str.strip()
    df["label"] = df["label"].astype(int)
    print(f"    Safe: {len(df[df['label']==0])}, Phishing: {len(df[df['label']==1])}")

    if len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
        print(f"    After sampling: {df.shape}")

    # Extract structured features
    print("    Extracting structured phishing features...")
    feature_dicts = df["text_combined"].apply(extract_phishing_features)
    features_df = pd.DataFrame(list(feature_dicts))

    # Save enhanced data
    enhanced = pd.concat([
        df[["text_combined", "label"]].reset_index(drop=True),
        features_df.reset_index(drop=True)
    ], axis=1)

    enhanced_path = os.path.join(PROCESSED_DIR, "phishing_enhanced.csv")
    enhanced.to_csv(enhanced_path, index=False)
    print(f"    Saved enhanced phishing data: {enhanced.shape} -> {enhanced_path}")

    # Also save basic for backward compatibility
    basic_path = os.path.join(PROCESSED_DIR, "phishing_processed.csv")
    df[["text_combined", "label"]].to_csv(basic_path, index=False)

    return enhanced


if __name__ == "__main__":
    print("=" * 60)
    print("ZeroTrust - Data Preprocessing Pipeline (v2)")
    print("=" * 60)
    preprocess_network_data()
    preprocess_phishing_data()
    print("\n[+] Data preprocessing complete.")
