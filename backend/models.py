"""SentinelLab – Database Models (VirusTotal-style)"""
import enum
from datetime import datetime, timezone
import json
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, Text,
    ForeignKey, Enum, BigInteger,
)
from sqlalchemy.orm import relationship
from backend.database import Base


class FileScan(Base):
    """Represents an uploaded + scanned file."""
    __tablename__ = "file_scans"

    id = Column(Integer, primary_key=True, index=True)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    sha1 = Column(String(40), nullable=False)
    md5 = Column(String(32), nullable=False)
    filename = Column(String(512), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    file_type = Column(String(128), default="unknown")
    mime_type = Column(String(128), default="application/octet-stream")
    magic_bytes = Column(String(64), default="")
    entropy = Column(Float, default=0.0)

    # Detection summary
    total_engines = Column(Integer, default=0)
    detections = Column(Integer, default=0)
    detection_ratio = Column(String(16), default="0/0")

    times_submitted = Column(Integer, default=1)
    
    # Async Scan Status
    status = Column(String(32), default="completed")  # queued, scanning, completed, failed
    analysis_id = Column(String(128), nullable=True)  # External analysis ID for polling
    
    vt_link = Column(String(256), default="")
    deep_analysis = Column(Text, default="{}")  # JSON string
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_scanned = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relations
    engine_results = relationship("EngineResult", back_populates="file_scan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
            "filename": self.filename,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "magic_bytes": self.magic_bytes,
            "entropy": round(self.entropy, 4),
            "total_engines": self.total_engines,
            "detections": self.detections,
            "detection_ratio": self.detection_ratio,
            "status": self.status,
            "vt_link": self.vt_link or f"https://www.virustotal.com/gui/file/{self.sha256}",
            "times_submitted": self.times_submitted,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_scanned": self.last_scanned.isoformat() if self.last_scanned else None,
            "engine_results": [r.to_dict() for r in self.engine_results] if self.engine_results else [],
            "deep_analysis": json.loads(self.deep_analysis) if self.deep_analysis else {},
        }


class EngineResult(Base):
    """Single AV engine result for a file scan."""
    __tablename__ = "engine_results"

    id = Column(Integer, primary_key=True, index=True)
    file_scan_id = Column(Integer, ForeignKey("file_scans.id"), nullable=False)
    engine_name = Column(String(64), nullable=False)
    engine_version = Column(String(32), default="1.0.0")
    detected = Column(Boolean, default=False)
    threat_name = Column(String(256), default=None, nullable=True)
    category = Column(String(64), default="clean")       # clean, malware, trojan, adware, pup, etc.
    confidence = Column(Float, default=0.0)
    scan_time_ms = Column(Float, default=0.0)

    file_scan = relationship("FileScan", back_populates="engine_results")

    def to_dict(self):
        return {
            "engine_name": self.engine_name,
            "engine_version": self.engine_version,
            "detected": self.detected,
            "threat_name": self.threat_name,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "scan_time_ms": round(self.scan_time_ms, 2),
        }
