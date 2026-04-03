"""Data models for URL Sandbox"""
from pydantic import BaseModel, HttpUrl, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime


class ScanRequest(BaseModel):
    """Request model for URL scanning"""
    url: HttpUrl
    force_rescan: bool = False
    timeout_override: Optional[int] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class VirusTotalFinding(BaseModel):
    """VirusTotal scan finding"""
    detection_count: int = 0
    undetected_count: int = 0
    suspicious_count: int = 0
    latest_scan_date: Optional[Any] = None
    categories: Optional[Dict[str, Any]] = None
    scan_id: Optional[str] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class URLScanFinding(BaseModel):
    """URLScan.io scan finding"""
    scan_uuid: Optional[str] = None
    screenshot_url: Optional[str] = None
    dom_text_length: int = 0
    page_title: Optional[str] = None
    http_status_code: Optional[int] = None
    page_domain: Optional[str] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = []
    ads: List[Dict[str, Any]] = []
    matches: Optional[Any] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class PlaywrightFinding(BaseModel):
    """Playwright browser analysis finding"""
    login_forms_detected: bool = False
    password_fields: int = 0
    suspicious_scripts: List[str] = []
    external_requests: List[Dict[str, str]] = []
    page_text_preview: Optional[str] = None
    final_url: Optional[str] = None
    redirect_count: int = 0
    response_time_ms: int = 0
    errors: List[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ScanFindings(BaseModel):
    """Combined findings from all scanners"""
    virustotal: Optional[VirusTotalFinding] = None
    urlscan: Optional[URLScanFinding] = None
    playwright: Optional[PlaywrightFinding] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


class ScanResponse(BaseModel):
    """Response model for URL scan"""
    scan_id: str
    url: str
    threat_score: int
    reason: str
    findings: ScanFindings
    timestamp: datetime
    warnings: List[str] = []

    model_config = ConfigDict(arbitrary_types_allowed=True)
