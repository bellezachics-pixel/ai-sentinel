from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisType(str, Enum):
    URL = "url"
    EMAIL = "email"
    FILE = "file"
    QR_CODE = "qr_code"
    NETWORK = "network"
    DEEPFAKE = "deepfake"
    FULL_SCAN = "full_scan"


class URLAnalysisRequest(BaseModel):
    url: str
    deep_scan: bool = False


class EmailAnalysisRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    body: str = ""
    headers: Optional[dict] = None


class FileAnalysisRequest(BaseModel):
    filename: str
    content_type: str = ""


class NetworkScanRequest(BaseModel):
    target_ip: Optional[str] = None
    check_arp: bool = True
    check_tls: bool = True
    check_dns: bool = True


class IdentityCheckRequest(BaseModel):
    value: str
    check_type: str = "email"  # email, phone, username, password


class ThreatIntelRequest(BaseModel):
    indicator: str
    indicator_type: str = "url"


class RiskScore(BaseModel):
    total: float = Field(ge=0, le=100)
    url_score: float = Field(default=0, ge=0, le=100)
    content_score: float = Field(default=0, ge=0, le=100)
    header_score: float = Field(default=0, ge=0, le=100)
    network_score: float = Field(default=0, ge=0, le=100)
    level: RiskLevel = RiskLevel.LOW
    breakdown: dict = {}


class ThreatIntelResult(BaseModel):
    source: str
    score: float = 0
    is_malicious: bool = False
    details: dict = {}
    raw_response: Optional[dict] = None


class AnalysisResult(BaseModel):
    id: str = ""
    analysis_type: AnalysisType
    target: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    risk_score: RiskScore
    findings: List[dict] = []
    threat_intel: List[ThreatIntelResult] = []
    recommendations: List[str] = []
    metadata: dict = {}


class NetworkIntegrityStatus(BaseModel):
    is_secure: bool = True
    tls_fingerprint: Optional[dict] = None
    arp_anomalies: List[dict] = []
    dns_anomalies: List[dict] = []
    latency_baseline: Optional[dict] = None
    risk_indicators: List[str] = []


class DashboardStats(BaseModel):
    total_scans: int = 0
    threats_detected: int = 0
    active_monitors: int = 0
    risk_distribution: dict = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }
    recent_analyses: List[AnalysisResult] = []
    network_status: NetworkIntegrityStatus = NetworkIntegrityStatus()
