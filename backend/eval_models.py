"""Complete ML model evaluation for README documentation."""
import os, sys, json, time
import pandas as pd, numpy as np
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import settings

output = {}

# ══════════════════════════════════════════════════════════════════════
# NETWORK ANOMALY DETECTION MODELS
# ══════════════════════════════════════════════════════════════════════
print("=" * 70)
print("NETWORK ANOMALY DETECTION MODEL EVALUATION")
print("=" * 70)

# Load models
sup_model = joblib.load(os.path.join(settings.MODELS_DIR, "supervised_network_model.pkl"))
if_model = joblib.load(os.path.join(settings.MODELS_DIR, "network_model.pkl"))
scaler = joblib.load(os.path.join(settings.PROCESSED_DIR, "network_scaler.pkl"))
features = joblib.load(os.path.join(settings.PROCESSED_DIR, "network_feature_columns.pkl"))

print(f"Feature columns: {len(features)}")
print(f"Supervised model: {type(sup_model).__name__}")
print(f"  n_estimators: {sup_model.n_estimators}")
print(f"  max_depth: {sup_model.max_depth}")
print(f"  class_weight: {sup_model.class_weight}")
print(f"Isolation Forest: {type(if_model).__name__}")
print(f"  n_estimators: {if_model.n_estimators}")
print(f"  contamination: {if_model.contamination}")

# Load pre-scaled test data (same split as training)
mixed = pd.read_csv(os.path.join(settings.PROCESSED_DIR, "network_mixed.csv"))
X = mixed[features].values.astype(float)
y = mixed["label"].values
print(f"\nMixed dataset: {len(mixed)} samples, {(y==1).sum()} attacks, {(y==0).sum()} normal")

# Use 50K samples for evaluation
np.random.seed(42)
idx = np.random.choice(len(X), min(50000, len(X)), replace=False)
X_eval, y_eval = X[idx], y[idx]
print(f"Evaluation set: {len(X_eval)} samples")

# Supervised RF
print("\n--- Random Forest (Supervised) ---")
t0 = time.perf_counter()
y_pred_sup = sup_model.predict(X_eval)
y_proba_sup = sup_model.predict_proba(X_eval)[:, 1]
sup_ms = round((time.perf_counter() - t0) * 1000, 1)

sup_results = {
    "accuracy": round(accuracy_score(y_eval, y_pred_sup), 4),
    "precision": round(precision_score(y_eval, y_pred_sup, zero_division=0), 4),
    "recall": round(recall_score(y_eval, y_pred_sup, zero_division=0), 4),
    "f1": round(f1_score(y_eval, y_pred_sup, zero_division=0), 4),
    "roc_auc": round(roc_auc_score(y_eval, y_proba_sup), 4),
    "pr_auc": round(average_precision_score(y_eval, y_proba_sup), 4),
    "inference_ms_50k": sup_ms,
}
print(f"  Accuracy:  {sup_results['accuracy']}")
print(f"  Precision: {sup_results['precision']}")
print(f"  Recall:    {sup_results['recall']}")
print(f"  F1:        {sup_results['f1']}")
print(f"  ROC-AUC:   {sup_results['roc_auc']}")
print(f"  PR-AUC:    {sup_results['pr_auc']}")
print(f"  Inference:  {sup_ms}ms for 50K samples")
cm = confusion_matrix(y_eval, y_pred_sup)
print(f"  Confusion Matrix: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")

# Isolation Forest
print("\n--- Isolation Forest (Unsupervised) ---")
t0 = time.perf_counter()
if_pred = if_model.predict(X_eval)
if_scores = if_model.decision_function(X_eval)
if_ms = round((time.perf_counter() - t0) * 1000, 1)

if_anomaly_scores = np.clip(0.5 - if_scores * 0.5, 0, 1)
if_pred_binary = (if_pred == -1).astype(int)

if_results = {
    "roc_auc": round(roc_auc_score(y_eval, if_anomaly_scores), 4),
    "anomaly_rate": round(if_pred_binary.mean(), 4),
    "precision_at_threshold": round(precision_score(y_eval, if_pred_binary, zero_division=0), 4),
    "recall_at_threshold": round(recall_score(y_eval, if_pred_binary, zero_division=0), 4),
    "inference_ms_50k": if_ms,
}
print(f"  ROC-AUC:   {if_results['roc_auc']}")
print(f"  Anomaly rate: {if_results['anomaly_rate']}")
print(f"  Precision: {if_results['precision_at_threshold']}")
print(f"  Recall:    {if_results['recall_at_threshold']}")
print(f"  Inference: {if_ms}ms for 50K samples")

# Hybrid
print("\n--- Hybrid (IF 0.4 + RF 0.6) ---")
IF_WEIGHT, SUP_WEIGHT = 0.4, 0.6
hybrid_scores = IF_WEIGHT * if_anomaly_scores + SUP_WEIGHT * y_proba_sup
hybrid_pred = (hybrid_scores > 0.5).astype(int)

hybrid_results = {
    "accuracy": round(accuracy_score(y_eval, hybrid_pred), 4),
    "precision": round(precision_score(y_eval, hybrid_pred, zero_division=0), 4),
    "recall": round(recall_score(y_eval, hybrid_pred, zero_division=0), 4),
    "f1": round(f1_score(y_eval, hybrid_pred, zero_division=0), 4),
    "roc_auc": round(roc_auc_score(y_eval, hybrid_scores), 4),
}
print(f"  Accuracy:  {hybrid_results['accuracy']}")
print(f"  Precision: {hybrid_results['precision']}")
print(f"  Recall:    {hybrid_results['recall']}")
print(f"  F1:        {hybrid_results['f1']}")
print(f"  ROC-AUC:   {hybrid_results['roc_auc']}")

# Real-world inference test (raw data -> API pipeline)
print("\n--- Real-World Inference (raw -> scaler -> model) ---")
raw = pd.read_csv(os.path.join(settings.DATASETS_DIR, "cicids2017_cleaned.csv"), nrows=200000)
for col in features:
    raw[col] = pd.to_numeric(raw[col], errors="coerce")
raw.replace([np.inf, -np.inf], np.nan, inplace=True)
raw.dropna(inplace=True)

all_attacks = raw[raw["Attack Type"] != "Normal Traffic"]
all_normals = raw[raw["Attack Type"] == "Normal Traffic"]

attack_sample = all_attacks.sample(n=min(2000, len(all_attacks)), random_state=42)
X_atk = scaler.transform(attack_sample[features].values.astype(float))
sup_probs_atk = sup_model.predict_proba(X_atk)[:, 1]

normal_sample = all_normals.sample(n=min(2000, len(all_normals)), random_state=42)
X_nrm = scaler.transform(normal_sample[features].values.astype(float))
sup_probs_nrm = sup_model.predict_proba(X_nrm)[:, 1]

realworld = {
    "attack_detection_rate_50": round(float((sup_probs_atk > 0.5).mean()), 4),
    "attack_detection_rate_30": round(float((sup_probs_atk > 0.3).mean()), 4),
    "attack_mean_probability": round(float(sup_probs_atk.mean()), 4),
    "false_positive_rate_50": round(float((sup_probs_nrm > 0.5).mean()), 4),
    "false_positive_rate_30": round(float((sup_probs_nrm > 0.3).mean()), 4),
    "normal_mean_probability": round(float(sup_probs_nrm.mean()), 4),
}
print(f"  Attack detection (>0.5): {realworld['attack_detection_rate_50']*100}%")
print(f"  Attack detection (>0.3): {realworld['attack_detection_rate_30']*100}%")
print(f"  False positive (>0.5):   {realworld['false_positive_rate_50']*100}%")
print(f"  Attack mean prob:        {realworld['attack_mean_probability']}")
print(f"  Normal mean prob:        {realworld['normal_mean_probability']}")

output["network"] = {
    "supervised_rf": sup_results,
    "isolation_forest": if_results,
    "hybrid": hybrid_results,
    "realworld_inference": realworld,
}

# ══════════════════════════════════════════════════════════════════════
# PHISHING DETECTION MODELS
# ══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("PHISHING DETECTION MODEL EVALUATION")
print("=" * 70)

phish_model = joblib.load(os.path.join(settings.MODELS_DIR, "phishing_model.pkl"))
phish_enhanced = joblib.load(os.path.join(settings.MODELS_DIR, "phishing_enhanced_model.pkl"))
vectorizer = joblib.load(os.path.join(settings.MODELS_DIR, "vectorizer.pkl"))
struct_scaler = joblib.load(os.path.join(settings.MODELS_DIR, "phishing_struct_scaler.pkl"))

print(f"Baseline model: {type(phish_model).__name__}")
print(f"Enhanced model: {type(phish_enhanced).__name__}")
print(f"TF-IDF vocab: {len(vectorizer.vocabulary_)} features")
print(f"TF-IDF ngram_range: {vectorizer.ngram_range}")

df_phish = pd.read_csv(os.path.join(settings.PROCESSED_DIR, "phishing_processed.csv"))
df_phish = df_phish.dropna(subset=["text_combined"])
df_phish["text_combined"] = df_phish["text_combined"].astype(str)
print(f"\nPhishing dataset: {len(df_phish)} samples")
print(f"  Safe: {(df_phish['label']==0).sum()}, Phishing: {(df_phish['label']==1).sum()}")

X_text = df_phish["text_combined"].values
y_phish = df_phish["label"].values
X_train, X_test, y_train, y_test = train_test_split(
    X_text, y_phish, test_size=0.2, random_state=42, stratify=y_phish
)

# Baseline
print("\n--- TF-IDF + Logistic Regression (Baseline) ---")
t0 = time.perf_counter()
X_test_tfidf = vectorizer.transform(X_test)
y_pred_base = phish_model.predict(X_test_tfidf)
y_proba_base = phish_model.predict_proba(X_test_tfidf)[:, 1]
base_ms = round((time.perf_counter() - t0) * 1000, 1)

baseline_results = {
    "accuracy": round(accuracy_score(y_test, y_pred_base), 4),
    "precision": round(precision_score(y_test, y_pred_base, zero_division=0), 4),
    "recall": round(recall_score(y_test, y_pred_base, zero_division=0), 4),
    "f1": round(f1_score(y_test, y_pred_base, zero_division=0), 4),
    "roc_auc": round(roc_auc_score(y_test, y_proba_base), 4),
    "pr_auc": round(average_precision_score(y_test, y_proba_base), 4),
    "inference_ms_10k": base_ms,
}
print(f"  Accuracy:  {baseline_results['accuracy']}")
print(f"  Precision: {baseline_results['precision']}")
print(f"  Recall:    {baseline_results['recall']}")
print(f"  F1:        {baseline_results['f1']}")
print(f"  ROC-AUC:   {baseline_results['roc_auc']}")
print(f"  PR-AUC:    {baseline_results['pr_auc']}")
cm = confusion_matrix(y_test, y_pred_base)
print(f"  Confusion Matrix: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")

# Enhanced
print("\n--- TF-IDF + Structured Features + LogReg (Enhanced) ---")
from data.preprocess import extract_phishing_features
from scipy.sparse import hstack

struct_names = [
    "url_count", "has_ip_url", "suspicious_tld", "urgency_count",
    "urgency_ratio", "has_html_form", "has_html_link", "char_entropy",
    "word_count", "exclamation_count", "question_count", "caps_ratio"
]
t0 = time.perf_counter()
X_test_struct = np.array([
    [extract_phishing_features(t)[k] for k in struct_names] for t in X_test
])
X_test_struct_scaled = struct_scaler.transform(X_test_struct)
X_test_combined = hstack([X_test_tfidf, X_test_struct_scaled])
y_pred_enh = phish_enhanced.predict(X_test_combined)
y_proba_enh = phish_enhanced.predict_proba(X_test_combined)[:, 1]
enh_ms = round((time.perf_counter() - t0) * 1000, 1)

enhanced_results = {
    "accuracy": round(accuracy_score(y_test, y_pred_enh), 4),
    "precision": round(precision_score(y_test, y_pred_enh, zero_division=0), 4),
    "recall": round(recall_score(y_test, y_pred_enh, zero_division=0), 4),
    "f1": round(f1_score(y_test, y_pred_enh, zero_division=0), 4),
    "roc_auc": round(roc_auc_score(y_test, y_proba_enh), 4),
    "pr_auc": round(average_precision_score(y_test, y_proba_enh), 4),
    "inference_ms_10k": enh_ms,
    "structured_features": struct_names,
}
print(f"  Accuracy:  {enhanced_results['accuracy']}")
print(f"  Precision: {enhanced_results['precision']}")
print(f"  Recall:    {enhanced_results['recall']}")
print(f"  F1:        {enhanced_results['f1']}")
print(f"  ROC-AUC:   {enhanced_results['roc_auc']}")
print(f"  PR-AUC:    {enhanced_results['pr_auc']}")
cm = confusion_matrix(y_test, y_pred_enh)
print(f"  Confusion Matrix: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")

output["phishing"] = {
    "baseline": baseline_results,
    "enhanced": enhanced_results,
}

# Save JSON results
out_path = os.path.join(settings.MODELS_DIR, "full_evaluation.json")
with open(out_path, "w") as f:
    json.dump(output, f, indent=2)
print(f"\nFull results saved to {out_path}")
print("\n[DONE] All evaluations complete.")
