"""
ZeroTrust - Dynamic Risk Engine (v2)
Time-aware trust scoring with exponential decay, sliding windows,
severity multipliers, and per-device rolling averages.
All risk calculations are deterministic and unit-testable.
"""

import math
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

logger = logging.getLogger("zerotrust.risk_engine")

# ─── Configuration ────────────────────────────────────────────────────────────

QUARANTINE_THRESHOLD = 50
SUSPICIOUS_THRESHOLD = 80
BASE_SCORE = 100

# Exponential decay half-life in seconds (5 minutes)
DECAY_HALF_LIFE = 300.0

# Sliding window for frequency escalation (seconds)
FREQUENCY_WINDOW = 600.0  # 10 minutes
FREQUENCY_ESCALATION_THRESHOLD = 3  # events to trigger escalation

# Severity multipliers by attack type
SEVERITY_MULTIPLIERS = {
    "ddos": 1.5,
    "brute_force": 1.3,
    "web_attack": 1.4,
    "port_scan": 1.1,
    "phishing": 1.2,
    "data_exfiltration": 1.8,
    "c2_communication": 1.6,
    "insider_threat": 1.4,
    "generic": 1.0,
}


# ─── Core Scoring Functions ───────────────────────────────────────────────────

def exponential_decay(age_seconds: float, half_life: float = DECAY_HALF_LIFE) -> float:
    """
    Calculate exponential decay weight for a past event.
    Returns 1.0 for age=0, 0.5 for age=half_life, approaches 0 for old events.
    """
    if age_seconds <= 0:
        return 1.0
    return math.pow(2, -age_seconds / half_life)


def calculate_frequency_escalation(recent_events: List[dict],
                                   window_seconds: float = FREQUENCY_WINDOW) -> float:
    """
    Calculate escalation multiplier based on event frequency in sliding window.
    Returns 1.0 for normal frequency, up to 2.0 for high frequency.
    """
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=window_seconds)

    count = 0
    for event in recent_events:
        ts = event.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                continue
        if isinstance(ts, datetime) and ts >= window_start:
            count += 1

    if count <= FREQUENCY_ESCALATION_THRESHOLD:
        return 1.0
    # Linear escalation: 3 events = 1.0x, 6 events = 1.5x, 10+ events = 2.0x
    escalation = 1.0 + min(1.0, (count - FREQUENCY_ESCALATION_THRESHOLD) / 7.0)
    return round(escalation, 3)


def get_severity_multiplier(attack_type: str = "generic") -> float:
    """Get severity multiplier for a given attack type."""
    if not attack_type:
        attack_type = "generic"
    return SEVERITY_MULTIPLIERS.get(attack_type.lower(), 1.0)


def calculate_trust_score(
    anomaly_detected: bool,
    anomaly_score: float,
    phishing_probability: float,
    attack_type: str = "generic",
    recent_events: Optional[List[dict]] = None,
    historical_scores: Optional[List[int]] = None,
) -> dict:
    """
    Calculate dynamic Trust Score using graduated penalties, time-decay,
    frequency escalation, and severity multipliers.

    Parameters:
        anomaly_detected: Binary anomaly flag from Isolation Forest
        anomaly_score: Continuous anomaly score (0.0-1.0)
        phishing_probability: Phishing probability (0.0-1.0)
        attack_type: Type of detected attack for severity weighting
        recent_events: Recent risk events for frequency escalation
        historical_scores: Recent trust scores for rolling average

    Returns:
        dict with trust_score, status, reason, penalty_breakdown
    """
    score = float(BASE_SCORE)
    reasons = []
    penalties = {}

    severity = get_severity_multiplier(attack_type)
    frequency_mult = 1.0
    if recent_events:
        frequency_mult = calculate_frequency_escalation(recent_events)

    combined_mult = severity * frequency_mult

    # ── Network Anomaly Penalty ───────────────────────────────────────────
    network_penalty = 0.0
    if anomaly_detected:
        network_penalty = 45.0 * combined_mult
        reasons.append(f"Network anomaly detected (severity x{severity:.1f})")
    elif anomaly_score > 0.35:
        network_penalty = anomaly_score * 40.0 * combined_mult
        reasons.append(f"Elevated anomaly score ({anomaly_score:.2f})")

    if network_penalty > 0:
        penalties["network"] = round(network_penalty, 1)
        score -= network_penalty

    # ── Phishing Penalty ──────────────────────────────────────────────────
    phishing_penalty = 0.0
    if phishing_probability > 0.7:
        phishing_penalty = 35.0 * combined_mult
        reasons.append(f"High phishing probability ({phishing_probability:.2f})")
    elif phishing_probability > 0.4:
        phishing_penalty = 20.0 * combined_mult
        reasons.append(f"Moderate phishing probability ({phishing_probability:.2f})")

    if phishing_penalty > 0:
        penalties["phishing"] = round(phishing_penalty, 1)
        score -= phishing_penalty

    # ── Frequency Escalation Penalty ──────────────────────────────────────
    if frequency_mult > 1.0:
        freq_penalty = (frequency_mult - 1.0) * 10.0
        penalties["frequency_escalation"] = round(freq_penalty, 1)
        score -= freq_penalty
        reasons.append(f"Repeated suspicious activity (x{frequency_mult:.1f})")

    # ── Rolling Average Smoothing ─────────────────────────────────────────
    score = max(0, min(100, score))
    final_score = int(round(score))

    if historical_scores and len(historical_scores) > 0:
        # Weight: 70% current, 30% rolling average of recent scores
        rolling_avg = sum(historical_scores) / len(historical_scores)
        blended = 0.7 * score + 0.3 * rolling_avg
        final_score = int(round(max(0, min(100, blended))))

    # ── Status Determination ──────────────────────────────────────────────
    if final_score >= SUSPICIOUS_THRESHOLD:
        status = "SAFE"
    elif final_score >= QUARANTINE_THRESHOLD:
        status = "SUSPICIOUS"
    else:
        status = "QUARANTINED"

    if not reasons:
        reasons.append("All checks passed - device operating normally")

    total_penalty = sum(penalties.values())

    return {
        "trust_score": final_score,
        "status": status,
        "reason": " | ".join(reasons),
        "penalty_breakdown": penalties,
        "total_penalty": round(total_penalty, 1),
        "severity_multiplier": severity,
        "frequency_multiplier": frequency_mult,
    }


def get_risk_level_color(status: str) -> str:
    """Map status to monochrome display intensity."""
    color_map = {
        "SAFE": "#FFFFFF",
        "SUSPICIOUS": "#A1A1A1",
        "QUARANTINED": "#666666",
    }
    return color_map.get(status, "#A1A1A1")


def should_isolate(trust_score: int) -> bool:
    """Determine if device should be automatically isolated."""
    return trust_score < QUARANTINE_THRESHOLD


def calculate_decay_weighted_score(events: List[dict]) -> float:
    """
    Calculate a time-decay-weighted risk score from historical events.
    More recent events carry higher weight.
    """
    if not events:
        return 0.0

    now = datetime.utcnow()
    weighted_sum = 0.0
    weight_sum = 0.0

    for event in events:
        ts = event.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                continue
        if not isinstance(ts, datetime):
            continue

        age = (now - ts).total_seconds()
        weight = exponential_decay(age)
        penalty = event.get("penalty_applied", 0.0)
        weighted_sum += penalty * weight
        weight_sum += weight

    if weight_sum == 0:
        return 0.0
    return round(weighted_sum / weight_sum, 2)
