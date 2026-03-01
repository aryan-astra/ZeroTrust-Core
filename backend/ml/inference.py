"""
ZeroTrust - ML Inference Module (v2)
Hybrid inference: Isolation Forest + Supervised + Enhanced Phishing.
Supports parallel batch inference, latency logging, and cached model loading.
"""

import os
import sys
import time
import logging
import numpy as np
import joblib
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

logger = logging.getLogger("zerotrust.inference")

# Cached model references
_network_model = None
_supervised_model = None
_network_scaler = None
_network_features = None
_phishing_model = None
_phishing_enhanced_model = None
_phishing_vectorizer = None
_phishing_struct_scaler = None

# Hybrid weights (configurable)
IF_WEIGHT = 0.4
SUP_WEIGHT = 0.6


def load_models():
    """Load all trained models into memory."""
    global _network_model, _supervised_model, _network_scaler, _network_features
    global _phishing_model, _phishing_enhanced_model, _phishing_vectorizer, _phishing_struct_scaler

    print("[*] Loading ML models...")

    def _load(name, path):
        if os.path.exists(path):
            obj = joblib.load(path)
            print(f"    Loaded: {name}")
            return obj
        print(f"    [!] Not found: {name} ({path})")
        return None

    _network_model = _load("Isolation Forest", os.path.join(settings.MODELS_DIR, "network_model.pkl"))
    _supervised_model = _load("Supervised RF", os.path.join(settings.MODELS_DIR, "supervised_network_model.pkl"))
    _network_scaler = _load("Network Scaler", os.path.join(settings.PROCESSED_DIR, "network_scaler.pkl"))
    _network_features = _load("Feature Columns", os.path.join(settings.PROCESSED_DIR, "network_feature_columns.pkl"))
    _phishing_model = _load("Phishing LogReg", os.path.join(settings.MODELS_DIR, "phishing_model.pkl"))
    _phishing_enhanced_model = _load("Phishing Enhanced", os.path.join(settings.MODELS_DIR, "phishing_enhanced_model.pkl"))
    _phishing_vectorizer = _load("TF-IDF Vectorizer", os.path.join(settings.MODELS_DIR, "vectorizer.pkl"))
    _phishing_struct_scaler = _load("Struct Scaler", os.path.join(settings.MODELS_DIR, "phishing_struct_scaler.pkl"))

    print(f"[+] Model loading complete. Features: {len(_network_features) if _network_features else 0}\n")


def predict_network_anomaly(features: dict) -> dict:
    """
    Hybrid network anomaly prediction.
    Combines Isolation Forest score and supervised attack probability.
    """
    if _network_model is None or _network_scaler is None:
        return {"anomaly_detected": False, "anomaly_score": 0.0, "raw_score": 0.0,
                "supervised_score": 0.0, "hybrid_score": 0.0, "inference_ms": 0}

    t0 = time.perf_counter()

    # Construct feature vector
    feature_vector = [float(features.get(col, 0.0)) for col in _network_features]
    X = np.array([feature_vector])
    X_scaled = _network_scaler.transform(X)

    # Isolation Forest
    prediction = _network_model.predict(X_scaled)[0]
    raw_score = _network_model.decision_function(X_scaled)[0]
    if_anomaly_score = max(0.0, min(1.0, 0.5 - raw_score * 0.5))

    # Supervised classifier
    sup_score = 0.0
    if _supervised_model is not None:
        sup_proba = _supervised_model.predict_proba(X_scaled)
        sup_score = float(sup_proba[0][1])

    # Hybrid score
    hybrid_score = IF_WEIGHT * if_anomaly_score + SUP_WEIGHT * sup_score

    inference_ms = round((time.perf_counter() - t0) * 1000, 2)
    logger.info(f"Network inference: {inference_ms}ms, hybrid={hybrid_score:.4f}")

    return {
        "anomaly_detected": bool(prediction == -1 or hybrid_score > 0.5),
        "anomaly_score": round(float(hybrid_score), 4),
        "isolation_forest_score": round(float(if_anomaly_score), 4),
        "supervised_score": round(float(sup_score), 4),
        "raw_score": round(float(raw_score), 4),
        "inference_ms": float(inference_ms),
    }


def predict_phishing(email_text: str) -> dict:
    """
    Enhanced phishing prediction with structured features.
    Falls back to basic TF-IDF model if enhanced is unavailable.
    """
    if _phishing_model is None or _phishing_vectorizer is None:
        return {"is_phishing": False, "phishing_probability": 0.0,
                "confidence": 0.0, "inference_ms": 0}

    t0 = time.perf_counter()
    clean_text = email_text.lower().strip()
    X_tfidf = _phishing_vectorizer.transform([clean_text])

    # Try enhanced model first
    if _phishing_enhanced_model is not None and _phishing_struct_scaler is not None:
        try:
            from data.preprocess import extract_phishing_features
            from scipy.sparse import hstack
            feats = extract_phishing_features(clean_text)
            struct_names = [
                "url_count", "has_ip_url", "suspicious_tld", "urgency_count",
                "urgency_ratio", "has_html_form", "has_html_link", "char_entropy",
                "word_count", "exclamation_count", "question_count", "caps_ratio"
            ]
            struct_vec = np.array([[feats[k] for k in struct_names]])
            struct_scaled = _phishing_struct_scaler.transform(struct_vec)
            X_combined = hstack([X_tfidf, struct_scaled])

            prediction = _phishing_enhanced_model.predict(X_combined)[0]
            probabilities = _phishing_enhanced_model.predict_proba(X_combined)[0]
            model_used = "enhanced"
        except Exception as e:
            logger.warning(f"Enhanced phishing fallback: {e}")
            prediction = _phishing_model.predict(X_tfidf)[0]
            probabilities = _phishing_model.predict_proba(X_tfidf)[0]
            model_used = "baseline"
    else:
        prediction = _phishing_model.predict(X_tfidf)[0]
        probabilities = _phishing_model.predict_proba(X_tfidf)[0]
        model_used = "baseline"

    phishing_prob = float(probabilities[1])
    confidence = float(max(probabilities))
    inference_ms = round((time.perf_counter() - t0) * 1000, 2)

    logger.info(f"Phishing inference ({model_used}): {inference_ms}ms, prob={phishing_prob:.4f}")

    return {
        "is_phishing": bool(prediction == 1),
        "phishing_probability": round(phishing_prob, 4),
        "confidence": round(confidence, 4),
        "model_used": model_used,
        "inference_ms": inference_ms,
    }


def batch_predict_network(feature_list: List[dict], max_workers: int = None) -> List[dict]:
    """Parallel batch inference for network anomaly detection (AMD EPYC optimization)."""
    workers = max_workers or settings.MAX_WORKERS
    t0 = time.perf_counter()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(predict_network_anomaly, feature_list))

    total_ms = round((time.perf_counter() - t0) * 1000, 2)
    logger.info(f"Batch network inference: {len(feature_list)} samples, {total_ms}ms total, {workers} workers")
    return results


def batch_predict_phishing(email_list: List[str], max_workers: int = None) -> List[dict]:
    """Parallel batch inference for phishing detection."""
    workers = max_workers or settings.MAX_WORKERS
    t0 = time.perf_counter()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(predict_phishing, email_list))

    total_ms = round((time.perf_counter() - t0) * 1000, 2)
    logger.info(f"Batch phishing inference: {len(email_list)} samples, {total_ms}ms total, {workers} workers")
    return results


def get_feature_columns():
    """Return expected network feature column names."""
    return _network_features if _network_features else []
