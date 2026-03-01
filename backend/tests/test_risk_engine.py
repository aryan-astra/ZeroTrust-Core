"""
ZeroTrust - Risk Engine Unit Tests
"""

import os
import sys
import pytest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from engine.risk_engine import calculate_trust_score, exponential_decay, calculate_frequency_escalation


class TestExponentialDecay:
    def test_zero_age(self):
        assert exponential_decay(0) == 1.0

    def test_at_half_life(self):
        result = exponential_decay(300, half_life=300)
        assert abs(result - 0.5) < 0.01

    def test_very_old(self):
        result = exponential_decay(10000, half_life=300)
        assert result < 0.001


class TestFrequencyEscalation:
    def test_no_events(self):
        assert calculate_frequency_escalation([]) == 1.0

    def test_few_events(self):
        """2 events within window < threshold (3), should return 1.0."""
        now = datetime.utcnow()
        events = [
            {"timestamp": now.isoformat()},
            {"timestamp": (now - timedelta(seconds=30)).isoformat()},
        ]
        assert calculate_frequency_escalation(events) == 1.0

    def test_many_events(self):
        """10 events within window > threshold, should escalate above 1.0."""
        now = datetime.utcnow()
        events = [
            {"timestamp": (now - timedelta(seconds=i * 10)).isoformat()}
            for i in range(10)
        ]
        result = calculate_frequency_escalation(events)
        assert result > 1.0


class TestTrustScore:
    def test_clean_device(self):
        result = calculate_trust_score(
            anomaly_detected=False,
            anomaly_score=0.0,
            phishing_probability=0.0,
        )
        assert result["trust_score"] == 100
        assert result["status"] == "SAFE"

    def test_anomaly_detected(self):
        result = calculate_trust_score(
            anomaly_detected=True,
            anomaly_score=0.8,
            phishing_probability=0.0,
        )
        # 100 - 45 = 55, which is < SUSPICIOUS_THRESHOLD (80)
        assert result["trust_score"] < 80
        assert result["status"] in ("SUSPICIOUS", "QUARANTINED")

    def test_high_phishing(self):
        result = calculate_trust_score(
            anomaly_detected=False,
            anomaly_score=0.0,
            phishing_probability=0.9,
        )
        # 100 - 35 = 65, which is < SUSPICIOUS_THRESHOLD (80)
        assert result["trust_score"] < 80
        assert result["status"] == "SUSPICIOUS"

    def test_combined_threat(self):
        result = calculate_trust_score(
            anomaly_detected=True,
            anomaly_score=0.9,
            phishing_probability=0.9,
        )
        # 100 - 45 - 35 = 20, well below quarantine threshold
        assert result["trust_score"] < 30
        assert result["status"] == "QUARANTINED"

    def test_attack_type_severity(self):
        base = calculate_trust_score(
            anomaly_detected=True,
            anomaly_score=0.7,
            phishing_probability=0.0,
        )
        ddos = calculate_trust_score(
            anomaly_detected=True,
            anomaly_score=0.7,
            phishing_probability=0.0,
            attack_type="ddos",
        )
        # DDoS severity multiplier should lower the score further
        assert ddos["trust_score"] <= base["trust_score"]

    def test_score_bounds(self):
        result = calculate_trust_score(
            anomaly_detected=True,
            anomaly_score=1.0,
            phishing_probability=1.0,
            attack_type="data_exfiltration",
        )
        assert 0 <= result["trust_score"] <= 100
