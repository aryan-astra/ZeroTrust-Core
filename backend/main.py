"""
ZeroTrust - FastAPI Backend (v2)
Enterprise API server with JWT auth, WebSocket streaming, rate limiting,
and hybrid ML inference pipeline.
"""

import os
import sys
import uuid
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import settings
from ml.inference import (
    load_models, predict_network_anomaly, predict_phishing,
    batch_predict_network, batch_predict_phishing, get_feature_columns
)
from engine.risk_engine import calculate_trust_score
from data.database import (
    init_db, upsert_device, log_activity, log_risk_event,
    get_all_devices, get_device, get_activity_log,
    get_device_stats, isolate_device, get_risk_events,
    get_device_timeline, search_devices
)
from auth import (
    authenticate_user, create_access_token, get_current_user,
    require_admin, require_analyst
)
from services.websocket import manager, broadcast_device_update, broadcast_alert, broadcast_risk_event

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("zerotrust.api")

# Rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT])


# --- Pydantic Models ---

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int

class NetworkAnalysisRequest(BaseModel):
    device_id: Optional[str] = None
    hostname: Optional[str] = "unknown"
    ip_address: Optional[str] = "0.0.0.0"
    features: Dict[str, float]
    attack_type: Optional[str] = None

class EmailAnalysisRequest(BaseModel):
    device_id: Optional[str] = None
    email_text: str

class DeviceAnalysisRequest(BaseModel):
    device_id: Optional[str] = None
    hostname: Optional[str] = "unknown"
    ip_address: Optional[str] = "0.0.0.0"
    mac_address: Optional[str] = "00:00:00:00:00:00"
    device_type: Optional[str] = "workstation"
    network_features: Optional[Dict[str, float]] = None
    email_text: Optional[str] = None
    attack_type: Optional[str] = None

class BatchNetworkRequest(BaseModel):
    items: List[Dict[str, float]]

class BatchEmailRequest(BaseModel):
    emails: List[str]

class IsolateRequest(BaseModel):
    device_id: str
    reason: Optional[str] = "Manual isolation"


# --- Application Lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize models and database on startup."""
    print("=" * 60)
    print("ZeroTrust - Enterprise Security Engine v2")
    print("=" * 60)
    init_db()
    load_models()
    logger.info("Backend ready — JWT auth, WebSocket, rate limiting active")
    print("[+] Backend ready.\n")
    yield
    print("\n[*] Shutting down ZeroTrust backend...")


# --- FastAPI App ---

app = FastAPI(
    title="ZeroTrust Security Engine",
    description="Enterprise AI-Powered Zero-Trust Campus Security Engine — Hybrid ML, Dynamic Risk Scoring, Real-Time Monitoring",
    version="2.0.0",
    lifespan=lifespan,
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Helpers ---

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _should_isolate(trust_score: float) -> bool:
    return trust_score < settings.QUARANTINE_THRESHOLD

def _get_status(trust_score: float) -> str:
    if trust_score >= 80:
        return "SAFE"
    elif trust_score >= 50:
        return "SUSPICIOUS"
    else:
        return "QUARANTINED"


# --- Auth Endpoints ---

@app.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest):
    """Authenticate and receive a JWT token."""
    user = authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
    )
    logger.info(f"Login: {user['username']} ({user['role']})")
    return TokenResponse(
        access_token=token,
        role=user["role"],
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
    )


@app.get("/auth/me", tags=["Authentication"])
async def get_me(user: dict = Depends(get_current_user)):
    """Get current authenticated user info."""
    return {"username": user["username"], "role": user["role"]}


# --- Health Endpoints ---

@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "ZeroTrust Security Engine",
        "version": "2.0.0",
        "status": "operational",
        "websocket_clients": manager.client_count,
        "timestamp": _now_iso(),
    }


@app.get("/health", tags=["Health"])
async def health_check():
    stats = get_device_stats()
    return {
        "status": "healthy",
        "devices": stats.get("total", 0),
        "ws_clients": manager.client_count,
        "timestamp": _now_iso(),
    }


# --- Analysis Endpoints ---

@app.post("/analyze/network", tags=["Analysis"])
@limiter.limit(settings.RATE_LIMIT)
async def analyze_network(request: Request, body: NetworkAnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze network traffic features using hybrid anomaly detection."""
    device_id = body.device_id or f"DEV-{uuid.uuid4().hex[:8].upper()}"
    t0 = time.perf_counter()

    # Hybrid inference
    network_result = predict_network_anomaly(body.features)

    # Dynamic trust scoring
    risk = calculate_trust_score(
        anomaly_detected=network_result["anomaly_detected"],
        anomaly_score=network_result["anomaly_score"],
        phishing_probability=0.0,
        attack_type=body.attack_type,
    )
    trust_score = risk["trust_score"]
    status = _get_status(trust_score)
    isolated = _should_isolate(trust_score)

    # Persist
    device_data = {
        "id": device_id, "hostname": body.hostname, "ip_address": body.ip_address,
        "trust_score": trust_score, "status": status,
        "reason": risk["reason"], "anomaly_score": network_result["anomaly_score"],
        "phishing_score": 0.0, "is_isolated": isolated,
    }
    upsert_device(device_data)
    log_activity(device_id=device_id, event_type="NETWORK_ANALYSIS",
                 trust_score=trust_score, status=status,
                 anomaly_score=network_result["anomaly_score"],
                 phishing_score=0.0, reason=risk["reason"])

    if network_result["anomaly_detected"]:
        log_risk_event(device_id=device_id, event_type=body.attack_type or "anomaly",
                       severity=risk.get("severity_multiplier", 1.0),
                       anomaly_score=network_result["anomaly_score"],
                       phishing_score=0.0,
                       penalty=risk.get("total_penalty", 0))

    # Broadcast to WebSocket clients
    response = {
        "device_id": device_id, "network_analysis": network_result,
        "trust_score": trust_score, "status": status, "reason": risk["reason"],
        "isolated": isolated, "inference_ms": network_result.get("inference_ms", 0),
        "timestamp": _now_iso(),
    }
    background_tasks.add_task(broadcast_device_update, response)

    if isolated:
        background_tasks.add_task(broadcast_alert, {
            "device_id": device_id, "alert_type": "quarantine",
            "trust_score": trust_score, "reason": risk["reason"],
        })

    return response


@app.post("/analyze/email", tags=["Analysis"])
@limiter.limit(settings.RATE_LIMIT)
async def analyze_email(request: Request, body: EmailAnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze email content using enhanced phishing detection."""
    device_id = body.device_id or f"DEV-{uuid.uuid4().hex[:8].upper()}"

    phishing_result = predict_phishing(body.email_text)

    risk = calculate_trust_score(
        anomaly_detected=False, anomaly_score=0.0,
        phishing_probability=phishing_result["phishing_probability"],
    )
    trust_score = risk["trust_score"]
    status = _get_status(trust_score)

    # Ensure device exists before logging activity (FK constraint)
    device_data = {
        "id": device_id, "hostname": f"email-{device_id}",
        "ip_address": "0.0.0.0",
        "trust_score": trust_score, "status": status,
        "reason": risk["reason"], "anomaly_score": 0.0,
        "phishing_score": phishing_result["phishing_probability"],
        "is_isolated": False,
    }
    upsert_device(device_data)

    log_activity(device_id=device_id, event_type="EMAIL_ANALYSIS",
                 trust_score=trust_score, status=status,
                 anomaly_score=0.0, phishing_score=phishing_result["phishing_probability"],
                 reason=risk["reason"])

    if phishing_result["is_phishing"]:
        log_risk_event(device_id=device_id, event_type="phishing",
                       severity=risk.get("severity_multiplier", 1.0),
                       anomaly_score=0.0,
                       phishing_score=phishing_result["phishing_probability"],
                       penalty=risk.get("total_penalty", 0))

    response = {
        "device_id": device_id, "phishing_analysis": phishing_result,
        "trust_score": trust_score, "status": status, "reason": risk["reason"],
        "inference_ms": phishing_result.get("inference_ms", 0),
        "timestamp": _now_iso(),
    }

    if phishing_result["is_phishing"]:
        background_tasks.add_task(broadcast_alert, {
            "device_id": device_id, "alert_type": "phishing",
            "probability": phishing_result["phishing_probability"],
        })

    return response


@app.post("/analyze/device", tags=["Analysis"])
@limiter.limit(settings.RATE_LIMIT)
async def analyze_device(request: Request, body: DeviceAnalysisRequest, background_tasks: BackgroundTasks):
    """Full device analysis combining network anomaly and phishing detection."""
    device_id = body.device_id or f"DEV-{uuid.uuid4().hex[:8].upper()}"

    # Network inference
    network_result = {"anomaly_detected": False, "anomaly_score": 0.0, "raw_score": 0.0,
                      "isolation_forest_score": 0.0, "supervised_score": 0.0, "inference_ms": 0}
    if body.network_features:
        network_result = predict_network_anomaly(body.network_features)

    # Phishing inference
    phishing_result = {"is_phishing": False, "phishing_probability": 0.0, "confidence": 0.0, "inference_ms": 0}
    if body.email_text:
        phishing_result = predict_phishing(body.email_text)

    # Combined risk
    risk = calculate_trust_score(
        anomaly_detected=network_result["anomaly_detected"],
        anomaly_score=network_result["anomaly_score"],
        phishing_probability=phishing_result["phishing_probability"],
        attack_type=body.attack_type,
    )
    trust_score = risk["trust_score"]
    status = _get_status(trust_score)
    isolated = _should_isolate(trust_score)

    # Persist
    device_data = {
        "id": device_id, "hostname": body.hostname, "ip_address": body.ip_address,
        "mac_address": body.mac_address, "device_type": body.device_type,
        "trust_score": trust_score, "status": status, "reason": risk["reason"],
        "anomaly_score": network_result["anomaly_score"],
        "phishing_score": phishing_result["phishing_probability"],
        "is_isolated": isolated,
    }
    upsert_device(device_data)

    event_type = "DEVICE_ANALYSIS"
    if isolated:
        event_type = "DEVICE_QUARANTINED"
    elif status == "SUSPICIOUS":
        event_type = "DEVICE_SUSPICIOUS"

    log_activity(device_id=device_id, event_type=event_type,
                 trust_score=trust_score, status=status,
                 anomaly_score=network_result["anomaly_score"],
                 phishing_score=phishing_result["phishing_probability"],
                 reason=risk["reason"])

    response = {
        "device_id": device_id, "hostname": body.hostname, "ip_address": body.ip_address,
        "network_analysis": network_result, "phishing_analysis": phishing_result,
        "trust_score": trust_score, "status": status, "reason": risk["reason"],
        "isolated": isolated, "timestamp": _now_iso(),
    }
    background_tasks.add_task(broadcast_device_update, response)
    return response


# --- Batch Endpoints ---

@app.post("/analyze/batch/network", tags=["Batch Analysis"])
@limiter.limit("20/minute")
async def batch_network(request: Request, body: BatchNetworkRequest):
    """Batch network anomaly detection (AMD EPYC multi-threaded)."""
    results = batch_predict_network(body.items)
    return {"results": results, "count": len(results), "timestamp": _now_iso()}


@app.post("/analyze/batch/email", tags=["Batch Analysis"])
@limiter.limit("20/minute")
async def batch_email(request: Request, body: BatchEmailRequest):
    """Batch phishing detection."""
    results = batch_predict_phishing(body.emails)
    return {"results": results, "count": len(results), "timestamp": _now_iso()}


# --- Device Management ---

@app.get("/devices", tags=["Devices"])
async def list_devices(
    query: Optional[str] = None,
    status: Optional[str] = None,
    sort: Optional[str] = "updated_at",
    limit: int = Query(default=100, le=500),
):
    """List devices with optional search, filtering, and sorting."""
    if query or status:
        devices = search_devices(query=query, status=status, sort_by=sort, limit=limit)
    else:
        devices = get_all_devices()

    stats = get_device_stats()
    return {"devices": devices, "stats": stats, "count": len(devices), "timestamp": _now_iso()}


@app.get("/devices/{device_id}", tags=["Devices"])
async def device_detail(device_id: str):
    """Get detailed device information with activity timeline."""
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
    timeline = get_device_timeline(device_id, limit=50)
    risk_events = get_risk_events(device_id=device_id, limit=20)
    return {"device": device, "timeline": timeline, "risk_events": risk_events, "timestamp": _now_iso()}


@app.post("/devices/{device_id}/isolate", tags=["Devices"])
async def isolate_device_endpoint(device_id: str, background_tasks: BackgroundTasks):
    """Manually isolate (quarantine) a device."""
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    isolate_device(device_id)
    log_activity(device_id=device_id, event_type="MANUAL_ISOLATION",
                 trust_score=0, status="QUARANTINED",
                 anomaly_score=0, phishing_score=0, reason="Manual admin isolation")

    background_tasks.add_task(broadcast_alert, {
        "device_id": device_id, "alert_type": "manual_isolation",
        "message": f"Device {device_id} manually quarantined",
    })

    return {"device_id": device_id, "status": "QUARANTINED", "isolated": True, "timestamp": _now_iso()}


# --- Activity & Events ---

@app.get("/activity", tags=["Activity"])
async def get_activity(limit: int = Query(default=50, le=200)):
    """Get recent activity log entries."""
    activities = get_activity_log(limit=limit)
    return {"activities": activities, "count": len(activities), "timestamp": _now_iso()}


@app.get("/risk-events", tags=["Activity"])
async def list_risk_events(
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=50, le=200),
):
    """Get risk events with optional filtering."""
    events = get_risk_events(device_id=device_id, limit=limit)
    if severity:
        events = [e for e in events if e.get("severity") == severity]
    return {"events": events, "count": len(events), "timestamp": _now_iso()}


# --- Stats ---

@app.get("/stats", tags=["Statistics"])
async def get_stats():
    """Get aggregate system statistics."""
    stats = get_device_stats()
    return {
        **stats,
        "ws_clients": manager.client_count,
        "timestamp": _now_iso(),
    }


@app.get("/features", tags=["Configuration"])
async def get_features():
    """Get expected network feature column names."""
    columns = get_feature_columns()
    return {"features": columns, "count": len(columns)}


# --- WebSocket ---

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time event streaming."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; optionally receive client messages
            data = await websocket.receive_text()
            if data == "ping":
                await manager.send_personal(websocket, {"type": "pong", "timestamp": _now_iso()})
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)
