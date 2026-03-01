"""
ZeroTrust - Database Layer (SQLAlchemy ORM)
MySQL-backed storage with SQLite fallback for device state, activity logs, and risk history.
Supports connection pooling and indexed queries.
"""

import os
import sys
import logging
from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Boolean,
    Text, DateTime, ForeignKey, Index, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

logger = logging.getLogger("zerotrust.database")

Base = declarative_base()


# ─── ORM Models ───────────────────────────────────────────────────────────────

class Device(Base):
    __tablename__ = "devices"

    id = Column(String(64), primary_key=True)
    hostname = Column(String(128), default="unknown")
    ip_address = Column(String(45), default="0.0.0.0")
    mac_address = Column(String(17), default="00:00:00:00:00:00")
    device_type = Column(String(32), default="workstation")
    trust_score = Column(Integer, default=100)
    status = Column(String(16), default="SAFE")
    reason = Column(Text, default="Initial registration")
    anomaly_score = Column(Float, default=0.0)
    phishing_score = Column(Float, default=0.0)
    is_isolated = Column(Boolean, default=False)
    last_activity = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("idx_device_status", "status"),
        Index("idx_device_trust", "trust_score"),
        Index("idx_device_updated", "updated_at"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "device_type": self.device_type,
            "trust_score": self.trust_score,
            "status": self.status,
            "reason": self.reason,
            "anomaly_score": self.anomaly_score,
            "phishing_score": self.phishing_score,
            "is_isolated": 1 if self.is_isolated else 0,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ActivityLog(Base):
    __tablename__ = "activity_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), ForeignKey("devices.id"), nullable=False)
    event_type = Column(String(32), nullable=False)
    trust_score = Column(Integer, default=100)
    status = Column(String(16), default="SAFE")
    anomaly_score = Column(Float, default=0.0)
    phishing_score = Column(Float, default=0.0)
    reason = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_activity_device", "device_id"),
        Index("idx_activity_timestamp", "timestamp"),
        Index("idx_activity_event", "event_type"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "event_type": self.event_type,
            "trust_score": self.trust_score,
            "status": self.status,
            "anomaly_score": self.anomaly_score,
            "phishing_score": self.phishing_score,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class RiskEvent(Base):
    """Historical risk signals for trend analytics and decay-based scoring."""
    __tablename__ = "risk_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), ForeignKey("devices.id"), nullable=False)
    event_type = Column(String(32), nullable=False)
    severity = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    phishing_score = Column(Float, default=0.0)
    penalty_applied = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_risk_device", "device_id"),
        Index("idx_risk_timestamp", "timestamp"),
    )

    def to_dict(self) -> dict:
        sev = self.severity or 0
        severity_label = "high" if sev >= 1.5 else ("medium" if sev >= 1.0 else "low")
        return {
            "id": self.id,
            "device_id": self.device_id,
            "event_type": self.event_type,
            "severity": severity_label,
            "severity_raw": self.severity,
            "anomaly_score": self.anomaly_score,
            "phishing_score": self.phishing_score,
            "penalty_applied": self.penalty_applied,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


# ─── Engine & Session ─────────────────────────────────────────────────────────

_engine = None
_SessionLocal = None


def _get_database_url() -> str:
    """Try MySQL first, fallback to SQLite."""
    try:
        import pymysql
        test_conn = pymysql.connect(
            host=settings.DB_HOST,
            port=settings.DB_PORT,
            user=settings.DB_USER,
            password=settings.DB_PASSWORD,
            connect_timeout=3
        )
        with test_conn.cursor() as cursor:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{settings.DB_NAME}`")
        test_conn.close()
        url = settings.DATABASE_URL
        logger.info(f"Using MySQL: {settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}")
        return url
    except Exception as e:
        sqlite_path = os.path.join(settings.BASE_DIR, "data", "zerotrust.db")
        os.makedirs(os.path.dirname(sqlite_path), exist_ok=True)
        url = f"sqlite:///{sqlite_path}"
        logger.warning(f"MySQL unavailable ({e}), using SQLite fallback")
        return url


def get_engine():
    global _engine
    if _engine is None:
        url = _get_database_url()
        if "sqlite" in url:
            _engine = create_engine(url, echo=False)
        else:
            _engine = create_engine(
                url, pool_size=10, max_overflow=20,
                pool_recycle=3600, pool_pre_ping=True, echo=False,
            )
    return _engine


def get_session() -> Session:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine())
    return _SessionLocal()


def init_db():
    """Create all tables using SQLAlchemy ORM."""
    engine = get_engine()
    Base.metadata.create_all(engine)
    print("[+] Database initialized (SQLAlchemy ORM).")


# ─── CRUD Operations ──────────────────────────────────────────────────────────

def upsert_device(device_data: dict):
    session = get_session()
    try:
        now = datetime.utcnow()
        device = session.query(Device).filter_by(id=device_data["id"]).first()
        if device:
            for key in ["trust_score", "status", "reason", "anomaly_score", "phishing_score",
                        "is_isolated", "hostname", "ip_address", "mac_address", "device_type"]:
                if key in device_data:
                    setattr(device, key, device_data[key])
            device.last_activity = now
            device.updated_at = now
        else:
            device = Device(
                id=device_data["id"],
                hostname=device_data.get("hostname", "unknown"),
                ip_address=device_data.get("ip_address", "0.0.0.0"),
                mac_address=device_data.get("mac_address", "00:00:00:00:00:00"),
                device_type=device_data.get("device_type", "workstation"),
                trust_score=device_data.get("trust_score", 100),
                status=device_data.get("status", "SAFE"),
                reason=device_data.get("reason", "Initial registration"),
                anomaly_score=device_data.get("anomaly_score", 0.0),
                phishing_score=device_data.get("phishing_score", 0.0),
                is_isolated=device_data.get("is_isolated", False),
                last_activity=now, created_at=now, updated_at=now,
            )
            session.add(device)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"upsert_device error: {e}")
        raise
    finally:
        session.close()


def log_activity(device_id: str, event_type: str, trust_score: int,
                 status: str, anomaly_score: float, phishing_score: float, reason: str):
    session = get_session()
    try:
        entry = ActivityLog(
            device_id=device_id, event_type=event_type, trust_score=trust_score,
            status=status, anomaly_score=anomaly_score, phishing_score=phishing_score,
            reason=reason, timestamp=datetime.utcnow(),
        )
        session.add(entry)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"log_activity error: {e}")
    finally:
        session.close()


def log_risk_event(device_id: str, event_type: str, severity: float,
                   anomaly_score: float, phishing_score: float, penalty: float):
    session = get_session()
    try:
        event = RiskEvent(
            device_id=device_id, event_type=event_type, severity=severity,
            anomaly_score=anomaly_score, phishing_score=phishing_score,
            penalty_applied=penalty, timestamp=datetime.utcnow(),
        )
        session.add(event)
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"log_risk_event error: {e}")
    finally:
        session.close()


def get_all_devices() -> list:
    session = get_session()
    try:
        devices = session.query(Device).order_by(Device.updated_at.desc()).all()
        return [d.to_dict() for d in devices]
    finally:
        session.close()


def get_device(device_id: str) -> Optional[dict]:
    session = get_session()
    try:
        device = session.query(Device).filter_by(id=device_id).first()
        return device.to_dict() if device else None
    finally:
        session.close()


def get_activity_log(limit: int = 100) -> list:
    session = get_session()
    try:
        entries = session.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(limit).all()
        return [e.to_dict() for e in entries]
    finally:
        session.close()


def get_risk_events(device_id: str = None, limit: int = 50) -> list:
    session = get_session()
    try:
        q = session.query(RiskEvent)
        if device_id:
            q = q.filter_by(device_id=device_id)
        events = q.order_by(RiskEvent.timestamp.desc()).limit(limit).all()
        return [e.to_dict() for e in events]
    finally:
        session.close()


def get_device_stats() -> dict:
    session = get_session()
    try:
        total = session.query(func.count(Device.id)).scalar() or 0
        safe = session.query(func.count(Device.id)).filter(Device.status == "SAFE").scalar() or 0
        suspicious = session.query(func.count(Device.id)).filter(Device.status == "SUSPICIOUS").scalar() or 0
        quarantined = session.query(func.count(Device.id)).filter(Device.status == "QUARANTINED").scalar() or 0
        avg_score = session.query(func.avg(Device.trust_score)).scalar()
        return {
            "total_devices": total,
            "safe_devices": safe,
            "suspicious_devices": suspicious,
            "quarantined_devices": quarantined,
            "average_trust_score": round(float(avg_score), 1) if avg_score else 100.0,
        }
    finally:
        session.close()


def isolate_device(device_id: str):
    session = get_session()
    try:
        device = session.query(Device).filter_by(id=device_id).first()
        if device:
            device.is_isolated = True
            device.status = "QUARANTINED"
            device.updated_at = datetime.utcnow()
            session.commit()
        log_activity(device_id, "DEVICE_ISOLATED", 0, "QUARANTINED", 0.0, 0.0,
                     "Device manually isolated by administrator")
    except Exception as e:
        session.rollback()
        logger.error(f"isolate_device error: {e}")
    finally:
        session.close()


def get_device_timeline(device_id: str, limit: int = 100) -> list:
    session = get_session()
    try:
        entries = (session.query(ActivityLog).filter_by(device_id=device_id)
                   .order_by(ActivityLog.timestamp.desc()).limit(limit).all())
        return [e.to_dict() for e in entries]
    finally:
        session.close()


def search_devices(query: str = "", status: str = "", sort_by: str = "updated_at",
                   sort_order: str = "desc", limit: int = 100) -> list:
    session = get_session()
    try:
        q = session.query(Device)
        if query:
            pattern = f"%{query}%"
            q = q.filter(
                (Device.id.like(pattern)) | (Device.hostname.like(pattern)) |
                (Device.ip_address.like(pattern))
            )
        if status:
            q = q.filter(Device.status == status.upper())
        sort_col = getattr(Device, sort_by, Device.updated_at)
        q = q.order_by(sort_col.asc() if sort_order == "asc" else sort_col.desc())
        return [d.to_dict() for d in q.limit(limit).all()]
    finally:
        session.close()
