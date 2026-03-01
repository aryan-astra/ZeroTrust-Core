"""Comprehensive API endpoint testing for ZeroTrust."""
import requests
import json
import time

BASE = "http://localhost:8000"
results = []

def test(name, method, url, json_body=None, expected_status=200):
    try:
        t0 = time.perf_counter()
        if method == "GET":
            r = requests.get(url, timeout=30)
        elif method == "POST":
            r = requests.post(url, json=json_body, timeout=30)
        ms = round((time.perf_counter() - t0) * 1000, 1)
        ok = r.status_code == expected_status
        status = "PASS" if ok else "FAIL"
        results.append((name, status, r.status_code, ms))
        detail = ""
        if ok and r.headers.get("content-type", "").startswith("application/json"):
            data = r.json()
            if isinstance(data, dict):
                keys = list(data.keys())[:6]
                detail = f" keys={keys}"
            elif isinstance(data, list):
                detail = f" items={len(data)}"
        print(f"  [{status}] {name:40s} -> {r.status_code} ({ms}ms){detail}")
        return r.json() if ok else None
    except Exception as e:
        results.append((name, "ERROR", 0, 0))
        print(f"  [ERROR] {name:40s} -> {e}")
        return None

print("=" * 70)
print("ZEROTRUST API COMPREHENSIVE TEST SUITE")
print("=" * 70)

# ── Health & Stats ──────────────────────────────────────────────────
print("\n--- Health & Stats ---")
health = test("GET /health", "GET", f"{BASE}/health")
stats = test("GET /stats", "GET", f"{BASE}/stats")

# ── Device Analysis ─────────────────────────────────────────────────
print("\n--- Device Analysis ---")
# Normal device
test("POST /analyze/device (normal)", "POST", f"{BASE}/analyze/device", {
    "device_id": "TEST-NORMAL-001",
    "hostname": "safe-laptop",
    "ip_address": "192.168.1.100",
    "network_features": {"Flow Duration": 1000, "Total Fwd Packets": 5}
})

# Attack device (realistic features)
test("POST /analyze/device (attack)", "POST", f"{BASE}/analyze/device", {
    "device_id": "TEST-ATTACK-001",
    "hostname": "suspicious-server",
    "ip_address": "10.0.0.99",
    "network_features": {
        "Destination Port": 22, "Flow Duration": 100000000,
        "Total Fwd Packets": 50000, "Total Length of Fwd Packets": 50000000,
        "Fwd Packet Length Max": 1500, "Fwd Packet Length Mean": 1000,
        "Bwd Packet Length Max": 0, "Flow Bytes/s": 500000000,
        "Flow Packets/s": 500000, "Fwd IAT Total": 100,
        "Fwd IAT Mean": 2, "Active Mean": 50000000,
        "Idle Mean": 0, "SYN Flag Count": 50000,
    }
})

# Minimal device
test("POST /analyze/device (minimal)", "POST", f"{BASE}/analyze/device", {
    "device_id": "TEST-MINIMAL-001",
    "hostname": "basic-device"
})

# ── Email/Phishing Analysis ────────────────────────────────────────
print("\n--- Email Analysis ---")
test("POST /analyze/email (phishing)", "POST", f"{BASE}/analyze/email", {
    "email_text": "URGENT: Your account has been compromised! Click here immediately to verify: http://evil-phishing.tk/login",
    "sender": "security@evil.tk",
    "device_id": "TEST-EMAIL-001"
})

test("POST /analyze/email (safe)", "POST", f"{BASE}/analyze/email", {
    "email_text": "Hi team, the quarterly report is attached. Please review and let me know your thoughts by Friday.",
    "sender": "colleague@company.com",
    "device_id": "TEST-EMAIL-002"
})

# ── Device Listing ─────────────────────────────────────────────────
print("\n--- Device Endpoints ---")
devices = test("GET /devices", "GET", f"{BASE}/devices")
test("GET /devices?status=SUSPICIOUS", "GET", f"{BASE}/devices?status=SUSPICIOUS")
test("GET /devices?search=attack", "GET", f"{BASE}/devices?search=attack")
test("GET /devices?sort_by=trust_score", "GET", f"{BASE}/devices?sort_by=trust_score")
test("GET /devices?limit=5", "GET", f"{BASE}/devices?limit=5")

# Get a specific device
if devices and "devices" in devices and len(devices["devices"]) > 0:
    did = devices["devices"][0]["id"]
    test(f"GET /devices/{did}", "GET", f"{BASE}/devices/{did}")

# ── Activity Log ───────────────────────────────────────────────────
print("\n--- Activity & Risk Events ---")
test("GET /activity", "GET", f"{BASE}/activity")
test("GET /activity?limit=5", "GET", f"{BASE}/activity?limit=5")
test("GET /risk-events", "GET", f"{BASE}/risk-events")
test("GET /risk-events?limit=5", "GET", f"{BASE}/risk-events?limit=5")

# ── Features ───────────────────────────────────────────────────────
print("\n--- Feature List ---")
features = test("GET /features", "GET", f"{BASE}/features")

# ── Isolate Device ─────────────────────────────────────────────────
print("\n--- Device Isolation ---")
test("POST /devices/TEST-ATTACK-001/isolate", "POST", f"{BASE}/devices/TEST-ATTACK-001/isolate", {
    "reason": "Automated test - suspicious activity detected"
})

# Verify isolation
isolated = test("GET /devices/TEST-ATTACK-001 (post-isolate)", "GET", f"{BASE}/devices/TEST-ATTACK-001")

# ── WebSocket Test ─────────────────────────────────────────────────
print("\n--- WebSocket ---")
try:
    import websocket
    ws = websocket.create_connection("ws://localhost:8000/ws", timeout=5)
    ws.close()
    results.append(("WS /ws connection", "PASS", 101, 0))
    print(f"  [PASS] {'WS /ws connection':40s} -> 101")
except ImportError:
    print(f"  [SKIP] {'WS /ws connection':40s} -> websocket-client not installed")
except Exception as e:
    results.append(("WS /ws connection", "FAIL", 0, 0))
    print(f"  [FAIL] {'WS /ws connection':40s} -> {e}")

# ── Summary ────────────────────────────────────────────────────────
print("\n" + "=" * 70)
passed = sum(1 for _, s, _, _ in results if s == "PASS")
failed = sum(1 for _, s, _, _ in results if s == "FAIL")
errors = sum(1 for _, s, _, _ in results if s == "ERROR")
total = len(results)
avg_ms = round(sum(ms for _, _, _, ms in results if ms > 0) / max(1, sum(1 for _, _, _, ms in results if ms > 0)), 1)
print(f"RESULTS: {passed}/{total} passed, {failed} failed, {errors} errors")
print(f"AVG LATENCY: {avg_ms}ms")
print("=" * 70)

# Print detailed results for failed tests
if failed > 0 or errors > 0:
    print("\nFAILED TESTS:")
    for name, status, code, ms in results:
        if status in ("FAIL", "ERROR"):
            print(f"  {name}: status={status}, code={code}")
