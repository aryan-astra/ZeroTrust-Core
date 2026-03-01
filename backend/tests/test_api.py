"""
ZeroTrust - API Integration Tests
Tests the FastAPI backend endpoints using httpx.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import app

client = TestClient(app)


class TestHealthEndpoints:
    def test_root(self):
        r = client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert data["service"] == "ZeroTrust Security Engine"
        assert data["version"] == "2.0.0"
        assert data["status"] == "operational"

    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"


class TestAuthEndpoints:
    def test_login_success(self):
        r = client.post("/auth/login", json={"username": "admin", "password": "admin123"})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert data["role"] == "admin"
        assert data["token_type"] == "bearer"

    def test_login_failure(self):
        r = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401

    def test_me_without_token(self):
        r = client.get("/auth/me")
        assert r.status_code in (401, 403)  # No bearer token

    def test_me_with_token(self):
        login = client.post("/auth/login", json={"username": "analyst", "password": "analyst123"})
        token = login.json()["access_token"]
        r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["username"] == "analyst"
        assert r.json()["role"] == "analyst"


class TestAnalysisEndpoints:
    def test_network_analysis(self):
        r = client.post("/analyze/network", json={
            "device_id": "TEST-NET-001",
            "hostname": "test-host",
            "ip_address": "10.0.1.100",
            "features": {"Flow Duration": 1000, "Total Fwd Packets": 5},
        })
        assert r.status_code == 200
        data = r.json()
        assert "trust_score" in data
        assert "network_analysis" in data
        assert "status" in data

    def test_email_analysis(self):
        r = client.post("/analyze/email", json={
            "device_id": "TEST-EMAIL-001",
            "email_text": "URGENT: Click here to reset your password http://evil.tk/hack",
        })
        assert r.status_code == 200
        data = r.json()
        assert "phishing_analysis" in data
        assert "trust_score" in data

    def test_device_analysis_combined(self):
        r = client.post("/analyze/device", json={
            "device_id": "TEST-DEV-001",
            "hostname": "test-workstation",
            "ip_address": "10.0.2.50",
            "network_features": {"Flow Duration": 500, "Total Fwd Packets": 10},
            "email_text": "Hi team, meeting at 3 PM tomorrow.",
        })
        assert r.status_code == 200
        data = r.json()
        assert "network_analysis" in data
        assert "phishing_analysis" in data
        assert "trust_score" in data

    def test_device_analysis_no_features(self):
        r = client.post("/analyze/device", json={
            "device_id": "TEST-EMPTY-001",
            "hostname": "empty",
        })
        assert r.status_code == 200


class TestDeviceEndpoints:
    def _create_device(self):
        client.post("/analyze/device", json={
            "device_id": "TEST-PERSIST-001",
            "hostname": "persist-host",
            "ip_address": "10.0.3.1",
            "network_features": {"Flow Duration": 200},
        })

    def test_list_devices(self):
        self._create_device()
        r = client.get("/devices")
        assert r.status_code == 200
        data = r.json()
        assert "devices" in data
        assert "stats" in data

    def test_list_devices_with_search(self):
        self._create_device()
        r = client.get("/devices", params={"query": "persist"})
        assert r.status_code == 200

    def test_device_detail(self):
        self._create_device()
        r = client.get("/devices/TEST-PERSIST-001")
        assert r.status_code == 200
        data = r.json()
        assert "device" in data
        assert "timeline" in data

    def test_device_not_found(self):
        r = client.get("/devices/NONEXISTENT-999")
        assert r.status_code == 404

    def test_isolate_device(self):
        self._create_device()
        r = client.post("/devices/TEST-PERSIST-001/isolate")
        assert r.status_code == 200
        assert r.json()["isolated"] is True


class TestActivityEndpoints:
    def test_activity_feed(self):
        r = client.get("/activity")
        assert r.status_code == 200
        assert "activities" in r.json()

    def test_risk_events(self):
        r = client.get("/risk-events")
        assert r.status_code == 200
        assert "events" in r.json()


class TestStatsEndpoints:
    def test_stats(self):
        r = client.get("/stats")
        assert r.status_code == 200
        data = r.json()
        assert "timestamp" in data

    def test_features(self):
        r = client.get("/features")
        assert r.status_code == 200
        assert "features" in r.json()
