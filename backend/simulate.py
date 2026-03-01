"""
ZeroTrust - Scenario-Driven Simulation Engine (v2)
Simulates realistic multi-stage attack campaigns and normal campus traffic
against the running backend API.

Scenarios:
  1. Normal campus traffic (baseline)
  2. DDoS attack ramp
  3. Phishing campaign
  4. Brute force intrusion
  5. Insider data exfiltration
  6. Multi-stage APT campaign (combines multiple attack types)
"""

import os
import sys
import time
import json
import random
import string
import asyncio
import argparse
import requests
import numpy as np
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import settings

API_BASE = f"http://localhost:{settings.SERVER_PORT}"

# ---- Load real training data for feature sampling ----
_attack_samples = None
_normal_samples = None
_feature_cols = None

def _load_feature_samples():
    """Load and cache real attack/normal feature samples from the processed dataset."""
    global _attack_samples, _normal_samples, _feature_cols
    if _feature_cols is not None:
        return
    try:
        import joblib
        import pandas as pd
        scaler = joblib.load(os.path.join(settings.PROCESSED_DIR, "network_scaler.pkl"))
        _feature_cols = joblib.load(os.path.join(settings.PROCESSED_DIR, "network_feature_columns.pkl"))
        mixed = pd.read_csv(os.path.join(settings.PROCESSED_DIR, "network_mixed.csv"))
        attacks = mixed[mixed["label"] == 1][_feature_cols].values
        normals = mixed[mixed["label"] == 0][_feature_cols].values
        _attack_samples = scaler.inverse_transform(attacks)
        _normal_samples = scaler.inverse_transform(normals)
    except Exception as e:
        print(f"  [!] Could not load feature samples: {e}. Using fallback values.")
        _attack_samples = None
        _normal_samples = None
        _feature_cols = []

_load_feature_samples()

# Device pools
HOSTNAMES = [
    "CAMPUS-WS-{:03d}", "LAB-PC-{:03d}", "LIBRARY-PC-{:03d}",
    "ADMIN-WS-{:03d}", "IOT-SENSOR-{:03d}", "PRINTER-{:03d}",
    "WIFI-AP-{:03d}", "SERVER-{:03d}", "KIOSK-{:03d}",
]
DEVICE_TYPES = ["workstation", "laptop", "iot_sensor", "printer", "server", "mobile"]
IP_SUBNETS = ["10.0.1", "10.0.2", "10.0.3", "10.0.4", "192.168.1"]

# Phishing email templates
PHISHING_EMAILS = [
    "URGENT: Your campus account has been compromised. Click here immediately to reset your password: http://192.168.1.100/reset",
    "Dear Student, Your financial aid is at risk of suspension. Verify your identity at http://campus-verify.tk/login now or lose access to your scholarship.",
    "IT Department Notice: We detected unauthorized access to your account. Please confirm your credentials at http://secure-campus.ml/verify within 24 hours.",
    "IMMEDIATE ACTION REQUIRED! Your email storage is 99% full. Click http://mail-upgrade.ga/storage to upgrade immediately or all emails will be deleted.",
    "Congratulations! You've won a $500 campus bookstore gift card. Claim your prize now at http://campus-rewards.xyz/claim before it expires!",
    "Warning: Suspicious login detected from unknown location. If this wasn't you, secure your account immediately: http://campus-security.pw/alert",
    "Your parking permit expires tomorrow. Renew now to avoid a $200 fine: http://parking.campus-services.cf/renew",
    "Professor notification: Your final grade has been updated. View your transcript: http://grades-portal.buzz/view?id=student",
]

SAFE_EMAILS = [
    "Hi team, just a reminder that the project meeting is scheduled for 3 PM tomorrow in Room 204. Please bring your laptops.",
    "The library will extend its hours during finals week. New hours: 7 AM - 2 AM. Study rooms can be reserved online.",
    "Campus IT maintenance is scheduled for Sunday 2 AM - 6 AM. Internet access may be intermittent during this window.",
    "Dear students, the career fair is next Thursday in the Student Center. Over 50 companies will be attending.",
    "Reminder: Research paper submissions are due by Friday at 11:59 PM. Late submissions will not be accepted.",
    "The campus shuttle schedule has been updated for the spring semester. Check the transportation website for details.",
    "Faculty meeting notes from Monday's session are now available on the department SharePoint.",
    "Welcome to the new semester! Please review the updated syllabus on the course management system.",
]


def _random_ip(subnet=None):
    s = subnet or random.choice(IP_SUBNETS)
    return f"{s}.{random.randint(2, 254)}"


def _random_mac():
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _random_device_id(prefix="DEV"):
    return f"{prefix}-{random.randint(1000, 9999)}"


def _random_hostname():
    return random.choice(HOSTNAMES).format(random.randint(1, 50))


def _normal_network_features():
    """Sample a real normal traffic row from the CICIDS-2017 processed training data."""
    if _normal_samples is not None and len(_normal_samples) > 0:
        row = _normal_samples[random.randint(0, len(_normal_samples) - 1)]
        return {col: float(row[i]) for i, col in enumerate(_feature_cols)}
    # Fallback: minimal synthetic dict if data could not be loaded
    fwd_pkt_mean = random.uniform(200, 1400)
    bwd_pkt_mean = random.uniform(100, 1200)
    pkt_mean = (fwd_pkt_mean + bwd_pkt_mean) / 2
    pkt_std = random.uniform(10, 300)
    flow_dur = random.uniform(5000, 2000000)       # microseconds
    fwd_pkts = random.randint(2, 25)
    bwd_pkts = random.randint(1, 20)
    iat_mean = flow_dur / max(fwd_pkts + bwd_pkts, 1)
    fwd_iat_mean = random.uniform(500, 80000)
    bwd_iat_mean = random.uniform(500, 80000)
    return {
        "Destination Port":          random.choice([80, 443, 8080, 53, 22, 25, 110, 143]),
        "Flow Duration":             flow_dur,
        "Total Fwd Packets":         fwd_pkts,
        "Total Length of Fwd Packets": fwd_pkts * fwd_pkt_mean,
        "Fwd Packet Length Max":     fwd_pkt_mean + random.uniform(0, 200),
        "Fwd Packet Length Min":     max(20, fwd_pkt_mean - random.uniform(0, 150)),
        "Fwd Packet Length Mean":    fwd_pkt_mean,
        "Fwd Packet Length Std":     random.uniform(5, 200),
        "Bwd Packet Length Max":     bwd_pkt_mean + random.uniform(0, 200),
        "Bwd Packet Length Min":     max(20, bwd_pkt_mean - random.uniform(0, 150)),
        "Bwd Packet Length Mean":    bwd_pkt_mean,
        "Bwd Packet Length Std":     random.uniform(5, 200),
        "Flow Bytes/s":              random.uniform(500, 80000),
        "Flow Packets/s":            random.uniform(1, 150),
        "Flow IAT Mean":             iat_mean,
        "Flow IAT Std":              iat_mean * random.uniform(0.1, 0.8),
        "Flow IAT Max":              iat_mean * random.uniform(1.5, 5),
        "Flow IAT Min":              random.uniform(10, 500),
        "Fwd IAT Total":             fwd_iat_mean * fwd_pkts,
        "Fwd IAT Mean":              fwd_iat_mean,
        "Fwd IAT Std":               fwd_iat_mean * random.uniform(0.1, 0.5),
        "Fwd IAT Max":               fwd_iat_mean * random.uniform(1.5, 4),
        "Fwd IAT Min":               random.uniform(10, 300),
        "Bwd IAT Total":             bwd_iat_mean * bwd_pkts,
        "Bwd IAT Mean":              bwd_iat_mean,
        "Bwd IAT Std":               bwd_iat_mean * random.uniform(0.1, 0.5),
        "Bwd IAT Max":               bwd_iat_mean * random.uniform(1.5, 4),
        "Bwd IAT Min":               random.uniform(10, 300),
        "Fwd Header Length":         random.uniform(20, 60),
        "Bwd Header Length":         random.uniform(20, 60),
        "Fwd Packets/s":             fwd_pkts / (flow_dur / 1e6 + 1e-9),
        "Bwd Packets/s":             bwd_pkts / (flow_dur / 1e6 + 1e-9),
        "Min Packet Length":         random.uniform(20, 100),
        "Max Packet Length":         pkt_mean + random.uniform(100, 600),
        "Packet Length Mean":        pkt_mean,
        "Packet Length Std":         pkt_std,
        "Packet Length Variance":    pkt_std ** 2,
        "FIN Flag Count":            random.randint(0, 1),
        "PSH Flag Count":            random.randint(0, 4),
        "ACK Flag Count":            random.randint(1, 12),
        "Average Packet Size":       pkt_mean,
        "Subflow Fwd Bytes":         fwd_pkts * fwd_pkt_mean,
        "Init_Win_bytes_forward":    random.randint(8192, 65535),
        "Init_Win_bytes_backward":   random.randint(8192, 65535),
        "act_data_pkt_fwd":          random.randint(1, fwd_pkts),
        "min_seg_size_forward":      random.randint(20, 32),
        "Active Mean":               random.uniform(0, 500000),
        "Active Max":                random.uniform(100000, 1000000),
        "Active Min":                random.uniform(0, 100000),
        "Idle Mean":                 random.uniform(0, 2000000),
        "Idle Max":                  random.uniform(500000, 5000000),
        "Idle Min":                  random.uniform(0, 500000),
    }


def _attack_network_features(attack_type):
    """Sample a real attack traffic row from the CICIDS-2017 processed training data."""
    if _attack_samples is not None and len(_attack_samples) > 0:
        row = _attack_samples[random.randint(0, len(_attack_samples) - 1)]
        return {col: float(row[i]) for i, col in enumerate(_feature_cols)}
    # Fallback: synthetic values if data could not be loaded
    base = _normal_network_features()

    if attack_type == "ddos":
        fwd_pkts = random.randint(1000, 50000)
        pkt_size = random.uniform(40, 80)
        flow_dur = random.uniform(100, 2000)
        base.update({
            "Destination Port":            random.choice([80, 443, 53]),
            "Flow Duration":               flow_dur,
            "Total Fwd Packets":           fwd_pkts,
            "Total Length of Fwd Packets": fwd_pkts * pkt_size,
            "Fwd Packet Length Max":       pkt_size + 4,
            "Fwd Packet Length Min":       pkt_size - 4,
            "Fwd Packet Length Mean":      pkt_size,
            "Fwd Packet Length Std":       random.uniform(0, 5),
            "Flow Bytes/s":                random.uniform(2000000, 15000000),
            "Flow Packets/s":              random.uniform(10000, 200000),
            "Fwd Packets/s":              fwd_pkts / (flow_dur / 1e6 + 1e-9),
            "Bwd Packets/s":              0,
            "Min Packet Length":           40,
            "Max Packet Length":           pkt_size + 10,
            "Packet Length Mean":          pkt_size,
            "Packet Length Std":           random.uniform(0, 5),
            "Packet Length Variance":      random.uniform(0, 25),
            "Average Packet Size":         pkt_size,
            "Subflow Fwd Bytes":           fwd_pkts * pkt_size,
            "FIN Flag Count":              0,
            "PSH Flag Count":              0,
            "ACK Flag Count":              0,
            "Init_Win_bytes_forward":      random.randint(1024, 4096),
            "Init_Win_bytes_backward":     0,
            "act_data_pkt_fwd":            fwd_pkts,
            "Flow IAT Mean":               flow_dur / max(fwd_pkts, 1),
            "Flow IAT Std":                1,
            "Flow IAT Max":                10,
            "Flow IAT Min":                0,
            "Idle Mean":                   0,
            "Idle Max":                    0,
            "Idle Min":                    0,
        })
    elif attack_type == "brute_force":
        fwd_pkts = random.randint(60, 300)
        bwd_pkts = random.randint(60, 300)
        pkt_size = random.uniform(40, 100)
        flow_dur = random.uniform(100000, 5000000)
        base.update({
            "Destination Port":            random.choice([22, 3389, 21, 23, 445]),
            "Flow Duration":               flow_dur,
            "Total Fwd Packets":           fwd_pkts,
            "Total Length of Fwd Packets": fwd_pkts * pkt_size,
            "Fwd Packet Length Mean":      pkt_size,
            "Fwd Packet Length Max":       pkt_size + 20,
            "Fwd Packet Length Min":       pkt_size - 10,
            "Fwd Packet Length Std":       random.uniform(2, 15),
            "Bwd Packet Length Mean":      pkt_size,
            "Bwd Packet Length Max":       pkt_size + 20,
            "Bwd Packet Length Min":       pkt_size - 10,
            "Bwd Packet Length Std":       random.uniform(2, 15),
            "Flow Bytes/s":                random.uniform(5000, 80000),
            "Flow Packets/s":              random.uniform(100, 2000),
            "Fwd Packets/s":              fwd_pkts / (flow_dur / 1e6 + 1e-9),
            "Bwd Packets/s":              bwd_pkts / (flow_dur / 1e6 + 1e-9),
            "Min Packet Length":           30,
            "Max Packet Length":           pkt_size + 30,
            "Packet Length Mean":          pkt_size,
            "Packet Length Std":           random.uniform(2, 20),
            "Packet Length Variance":      random.uniform(4, 400),
            "Average Packet Size":         pkt_size,
            "Subflow Fwd Bytes":           fwd_pkts * pkt_size,
            "FIN Flag Count":              random.randint(10, 50),
            "PSH Flag Count":              random.randint(0, 5),
            "ACK Flag Count":              random.randint(60, 300),
            "Init_Win_bytes_forward":      random.randint(8192, 65535),
            "Init_Win_bytes_backward":     random.randint(8192, 65535),
            "act_data_pkt_fwd":            random.randint(30, fwd_pkts),
        })
    elif attack_type == "web_attack":
        fwd_pkts = random.randint(10, 80)
        pkt_size = random.uniform(800, 5000)
        flow_dur = random.uniform(50000, 500000)
        base.update({
            "Destination Port":            random.choice([80, 443, 8080, 8443]),
            "Flow Duration":               flow_dur,
            "Total Fwd Packets":           fwd_pkts,
            "Total Length of Fwd Packets": fwd_pkts * pkt_size,
            "Fwd Packet Length Mean":      pkt_size,
            "Fwd Packet Length Max":       pkt_size + random.uniform(200, 1000),
            "Fwd Packet Length Min":       random.uniform(40, 100),
            "Fwd Packet Length Std":       random.uniform(200, 1000),
            "Flow Bytes/s":                random.uniform(80000, 800000),
            "Flow Packets/s":              random.uniform(50, 1000),
            "Min Packet Length":           40,
            "Max Packet Length":           pkt_size + 1000,
            "Packet Length Mean":          pkt_size,
            "Packet Length Std":           random.uniform(200, 1500),
            "Packet Length Variance":      random.uniform(40000, 2000000),
            "Average Packet Size":         pkt_size,
            "Subflow Fwd Bytes":           fwd_pkts * pkt_size,
            "PSH Flag Count":              random.randint(8, 40),
            "ACK Flag Count":              random.randint(10, 80),
            "FIN Flag Count":              random.randint(0, 5),
        })
    elif attack_type == "data_exfiltration":
        fwd_pkts = random.randint(200, 800)
        pkt_size = random.uniform(1200, 1500)
        flow_dur = random.uniform(60000000, 300000000)
        base.update({
            "Destination Port":            random.choice([443, 8443, 4444, 9001]),
            "Flow Duration":               flow_dur,
            "Total Fwd Packets":           fwd_pkts,
            "Total Length of Fwd Packets": fwd_pkts * pkt_size,
            "Fwd Packet Length Mean":      pkt_size,
            "Fwd Packet Length Max":       1500,
            "Fwd Packet Length Min":       pkt_size - 100,
            "Fwd Packet Length Std":       random.uniform(5, 50),
            "Flow Bytes/s":                random.uniform(200000, 2000000),
            "Flow Packets/s":              random.uniform(50, 500),
            "Fwd Packets/s":              fwd_pkts / (flow_dur / 1e6 + 1e-9),
            "Min Packet Length":           pkt_size - 150,
            "Max Packet Length":           1500,
            "Packet Length Mean":          pkt_size,
            "Packet Length Std":           random.uniform(5, 50),
            "Packet Length Variance":      random.uniform(25, 2500),
            "Average Packet Size":         pkt_size,
            "Subflow Fwd Bytes":           fwd_pkts * pkt_size,
            "Init_Win_bytes_forward":      random.randint(50000, 65535),
            "Init_Win_bytes_backward":     random.randint(8192, 32768),
            "act_data_pkt_fwd":            fwd_pkts,
            "PSH Flag Count":              random.randint(5, 30),
            "ACK Flag Count":              random.randint(100, 500),
            "Idle Mean":                   0,
            "Idle Max":                    0,
            "Idle Min":                    0,
        })
    elif attack_type == "port_scan":
        flow_dur = random.uniform(1, 200)
        base.update({
            "Destination Port":            random.randint(1, 65535),
            "Flow Duration":               flow_dur,
            "Total Fwd Packets":           random.randint(1, 3),
            "Total Length of Fwd Packets": random.uniform(40, 120),
            "Fwd Packet Length Mean":      random.uniform(40, 60),
            "Fwd Packet Length Max":       66,
            "Fwd Packet Length Min":       40,
            "Fwd Packet Length Std":       0,
            "Bwd Packet Length Mean":      0,
            "Bwd Packet Length Max":       0,
            "Bwd Packet Length Min":       0,
            "Bwd Packet Length Std":       0,
            "Flow Bytes/s":                random.uniform(50000, 500000),
            "Flow Packets/s":              random.uniform(5000, 100000),
            "Fwd Packets/s":              random.uniform(5000, 100000),
            "Bwd Packets/s":              0,
            "Min Packet Length":           40,
            "Max Packet Length":           66,
            "Packet Length Mean":          50,
            "Packet Length Std":           0,
            "Packet Length Variance":      0,
            "Average Packet Size":         50,
            "Subflow Fwd Bytes":           random.uniform(40, 120),
            "FIN Flag Count":              0,
            "PSH Flag Count":              0,
            "ACK Flag Count":              0,
            "Init_Win_bytes_forward":      random.randint(1024, 8192),
            "Init_Win_bytes_backward":     0,
            "act_data_pkt_fwd":            1,
            "Idle Mean":                   0,
            "Idle Max":                    0,
            "Idle Min":                    0,
            "Active Mean":                 0,
            "Active Max":                  0,
            "Active Min":                  0,
        })

    return base


def _send_device_analysis(device_id, hostname, ip, features, email_text=None, attack_type=None):
    """Send a device analysis request to the API."""
    payload = {
        "device_id": device_id,
        "hostname": hostname,
        "ip_address": ip,
        "mac_address": _random_mac(),
        "device_type": random.choice(DEVICE_TYPES),
        "network_features": features,
        "attack_type": attack_type,
    }
    if email_text:
        payload["email_text"] = email_text

    try:
        r = requests.post(f"{API_BASE}/analyze/device", json=payload, timeout=10)
        if r.status_code == 429:
            print(f"  [RATE-LIMITED] {device_id}: retrying...")
            time.sleep(1)
            r = requests.post(f"{API_BASE}/analyze/device", json=payload, timeout=10)
        data = r.json()
        status = data.get("status", "?")
        score = data.get("trust_score", "?")
        isolated = data.get("isolated", False)
        tag = "[QUARANTINE]" if isolated else f"[{status}]"
        print(f"  {tag:14s} {device_id:12s} | score={score:>6} | {hostname}")
        return data
    except Exception as e:
        print(f"  [ERROR] {device_id}: {e}")
        return None


def _send_email_analysis(device_id, email_text):
    """Send an email analysis request."""
    try:
        r = requests.post(f"{API_BASE}/analyze/email", json={
            "device_id": device_id,
            "email_text": email_text,
        }, timeout=10)
        if r.status_code == 429:
            print(f"  [RATE-LIMITED] {device_id}: retrying...")
            time.sleep(1)
            r = requests.post(f"{API_BASE}/analyze/email", json={
                "device_id": device_id,
                "email_text": email_text,
            }, timeout=10)
        data = r.json()
        prob = data.get("phishing_analysis", {}).get("phishing_probability", 0)
        is_phish = data.get("phishing_analysis", {}).get("is_phishing", False)
        tag = "[PHISHING]" if is_phish else "[SAFE]"
        print(f"  {tag:14s} {device_id:12s} | prob={prob:.4f}")
        return data
    except Exception as e:
        print(f"  [ERROR] {device_id}: {e}")
        return None


# ==================== SCENARIOS ====================

def scenario_normal_traffic(count=20, delay=0.3):
    """Scenario 1: Normal campus traffic baseline."""
    print("\n" + "=" * 60)
    print("SCENARIO: NORMAL CAMPUS TRAFFIC")
    print(f"  Devices: {count} | Delay: {delay}s")
    print("=" * 60)

    for i in range(count):
        device_id = _random_device_id("NORM")
        hostname = _random_hostname()
        ip = _random_ip()
        features = _normal_network_features()

        # Occasionally include a safe email
        email = random.choice(SAFE_EMAILS) if random.random() < 0.2 else None
        _send_device_analysis(device_id, hostname, ip, features, email_text=email)
        time.sleep(delay)


def scenario_ddos_attack(target_count=15, ramp_waves=3, delay=0.2):
    """Scenario 2: DDoS attack with escalating intensity."""
    print("\n" + "=" * 60)
    print("SCENARIO: DDoS ATTACK RAMP")
    print(f"  Targets: {target_count} | Waves: {ramp_waves}")
    print("=" * 60)

    target_ip = "10.0.1.100"
    for wave in range(1, ramp_waves + 1):
        print(f"\n  --- Wave {wave}/{ramp_waves} (intensity x{wave}) ---")
        attackers = target_count * wave
        for i in range(attackers):
            device_id = _random_device_id("DDOS")
            features = _attack_network_features("ddos")
            # Amplify with wave intensity
            features["Flow Packets/s"] *= wave
            features["Total Fwd Packets"] *= wave
            _send_device_analysis(device_id, f"BOTNET-{wave}-{i:03d}", _random_ip(), features, attack_type="ddos")
            time.sleep(delay / wave)


def scenario_phishing_campaign(count=15, delay=0.5):
    """Scenario 3: Targeted phishing campaign."""
    print("\n" + "=" * 60)
    print("SCENARIO: PHISHING CAMPAIGN")
    print(f"  Emails: {count}")
    print("=" * 60)

    for i in range(count):
        device_id = _random_device_id("PHSH")
        # Mix of phishing and safe emails (70% phishing)
        if random.random() < 0.7:
            email = random.choice(PHISHING_EMAILS)
        else:
            email = random.choice(SAFE_EMAILS)
        _send_email_analysis(device_id, email)
        time.sleep(delay)


def scenario_brute_force(target_device="SERVER-001", attempts=20, delay=0.2):
    """Scenario 4: Brute force login attempts against a single server."""
    print("\n" + "=" * 60)
    print(f"SCENARIO: BRUTE FORCE INTRUSION ({target_device})")
    print(f"  Attempts: {attempts}")
    print("=" * 60)

    target_ip = "10.0.1.10"
    for i in range(attempts):
        device_id = f"BF-{i + 1:04d}"
        features = _attack_network_features("brute_force")
        _send_device_analysis(device_id, f"ATTACKER-{i:03d}", _random_ip("10.0.3"),
                              features, attack_type="brute_force")
        time.sleep(delay)


def scenario_insider_exfiltration(stages=5, delay=1.0):
    """Scenario 5: Insider threat with gradual data exfiltration."""
    print("\n" + "=" * 60)
    print("SCENARIO: INSIDER DATA EXFILTRATION")
    print(f"  Stages: {stages}")
    print("=" * 60)

    insider_id = "INSIDER-001"
    insider_ip = "10.0.2.50"

    for stage in range(1, stages + 1):
        print(f"\n  --- Stage {stage}/{stages} ---")

        if stage <= 2:
            # Reconnaissance - normal-ish traffic with port scanning
            features = _attack_network_features("port_scan")
            _send_device_analysis(insider_id, "ADMIN-WS-042", insider_ip, features, attack_type="port_scan")
        elif stage <= 4:
            # Data gathering - increasing data transfer
            features = _attack_network_features("data_exfiltration")
            features["Flow Bytes/s"] *= stage
            _send_device_analysis(insider_id, "ADMIN-WS-042", insider_ip, features, attack_type="data_exfiltration")
        else:
            # Final exfiltration burst
            features = _attack_network_features("data_exfiltration")
            features["Flow Bytes/s"] *= 10
            features["Total Fwd Packets"] *= 5
            _send_device_analysis(insider_id, "ADMIN-WS-042", insider_ip, features, attack_type="data_exfiltration")

        time.sleep(delay)


def scenario_apt_campaign(delay=0.5):
    """Scenario 6: Multi-stage APT campaign combining multiple attack vectors."""
    print("\n" + "=" * 60)
    print("SCENARIO: MULTI-STAGE APT CAMPAIGN")
    print("=" * 60)

    apt_id = "APT-TARGET-001"
    apt_ip = "10.0.1.200"

    # Stage 1: Initial phishing to gain foothold
    print("\n  --- Stage 1: Initial Access (Phishing) ---")
    _send_email_analysis(apt_id, random.choice(PHISHING_EMAILS))
    time.sleep(delay)

    # Stage 2: Reconnaissance scanning
    print("\n  --- Stage 2: Reconnaissance ---")
    for i in range(3):
        features = _attack_network_features("port_scan")
        _send_device_analysis(apt_id, "COMPROMISED-WS", apt_ip, features, attack_type="port_scan")
        time.sleep(delay)

    # Stage 3: Lateral movement (web attacks)
    print("\n  --- Stage 3: Lateral Movement ---")
    for i in range(3):
        features = _attack_network_features("web_attack")
        _send_device_analysis(f"LATERAL-{i:03d}", f"PIVOT-NODE-{i}", _random_ip("10.0.2"),
                              features, attack_type="web_attack")
        time.sleep(delay)

    # Stage 4: Privilege escalation (brute force)
    print("\n  --- Stage 4: Privilege Escalation ---")
    for i in range(5):
        features = _attack_network_features("brute_force")
        _send_device_analysis(apt_id, "COMPROMISED-WS", apt_ip, features, attack_type="brute_force")
        time.sleep(delay * 0.5)

    # Stage 5: Data exfiltration
    print("\n  --- Stage 5: Data Exfiltration ---")
    for i in range(3):
        features = _attack_network_features("data_exfiltration")
        features["Flow Bytes/s"] *= (i + 1) * 3
        _send_device_analysis(apt_id, "COMPROMISED-WS", apt_ip, features, attack_type="data_exfiltration")
        time.sleep(delay)

    # Stage 6: Additional phishing (persistence)
    print("\n  --- Stage 6: Persistence (More Phishing) ---")
    for i in range(3):
        _send_email_analysis(f"PERSIST-{i:03d}", random.choice(PHISHING_EMAILS))
        time.sleep(delay)


def run_full_demo():
    """Run all scenarios with a summary."""
    print("\n" + "#" * 60)
    print("# ZEROTRUST v2 - FULL SIMULATION DEMO")
    print(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("#" * 60)

    t0 = time.time()

    scenario_normal_traffic(count=10, delay=0.2)
    scenario_ddos_attack(target_count=5, ramp_waves=2, delay=0.15)
    scenario_phishing_campaign(count=10, delay=0.3)
    scenario_brute_force(attempts=10, delay=0.15)
    scenario_insider_exfiltration(stages=4, delay=0.5)
    scenario_apt_campaign(delay=0.3)

    elapsed = time.time() - t0

    # Fetch final stats
    try:
        stats = requests.get(f"{API_BASE}/stats", timeout=5).json()
        print("\n" + "=" * 60)
        print("SIMULATION COMPLETE")
        print(f"  Duration: {elapsed:.1f}s")
        print(f"  Total devices: {stats.get('total_devices', '?')}")
        print(f"  Safe: {stats.get('safe_devices', '?')}")
        print(f"  Suspicious: {stats.get('suspicious_devices', '?')}")
        print(f"  Quarantined: {stats.get('quarantined_devices', '?')}")
        print("=" * 60)
    except Exception:
        print(f"\nSimulation complete in {elapsed:.1f}s")


SCENARIOS = {
    "normal": scenario_normal_traffic,
    "ddos": scenario_ddos_attack,
    "phishing": scenario_phishing_campaign,
    "brute_force": scenario_brute_force,
    "insider": scenario_insider_exfiltration,
    "apt": scenario_apt_campaign,
    "all": run_full_demo,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroTrust Simulation Engine v2")
    parser.add_argument("scenario", choices=list(SCENARIOS.keys()), default="all", nargs="?",
                        help="Scenario to run (default: all)")
    parser.add_argument("--count", type=int, default=None, help="Number of events")
    parser.add_argument("--delay", type=float, default=None, help="Delay between events (seconds)")
    args = parser.parse_args()

    fn = SCENARIOS[args.scenario]
    kwargs = {}
    if args.count:
        # Map to the right parameter name depending on scenario
        if args.scenario in ("normal", "phishing"):
            kwargs["count"] = args.count
        elif args.scenario == "brute_force":
            kwargs["attempts"] = args.count
        elif args.scenario == "insider":
            kwargs["stages"] = args.count
    if args.delay:
        kwargs["delay"] = args.delay

    fn(**kwargs)
