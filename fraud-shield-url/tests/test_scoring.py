"""Tests for risk scoring logic"""
import pytest
from scoring import RiskScorer
from models import ScanFindings, VirusTotalFinding, URLScanFinding, PlaywrightFinding

def test_risk_scorer_initialization():
    """Test scorer initialization"""
    scorer = RiskScorer()
    assert scorer.vt_weight == 0.35
    assert scorer.urlscan_weight == 0.35
    assert scorer.playwright_weight == 0.30

def test_virustotal_scoring():
    """Test VirusTotal score calculation"""
    scorer = RiskScorer()
    
    # Test high detections
    vt = VirusTotalFinding(detection_count=10, undetected_count=0, suspicious_count=0)
    score = scorer._score_virustotal(vt)
    assert score >= 90
    
    # Test low detections
    vt = VirusTotalFinding(detection_count=0, undetected_count=50, suspicious_count=0)
    score = scorer._score_virustotal(vt)
    assert score <= 10

def test_urlscan_scoring():
    """Test URLScan scoring"""
    scorer = RiskScorer()
    
    # Test no redirects
    urlscan = URLScanFinding(redirect_chain=[])
    score = scorer._score_urlscan(urlscan)
    assert score < 20
    
    # Test multiple redirects
    urlscan = URLScanFinding(redirect_chain=["a", "b", "c", "d"])
    score = scorer._score_urlscan(urlscan)
    assert score > 40

def test_playwright_scoring():
    """Test Playwright scoring"""
    scorer = RiskScorer()
    
    # Test no forms
    pw = PlaywrightFinding(login_forms_detected=False, password_fields=0)
    score = scorer._score_playwright(pw)
    assert score < 20
    
    # Test login form detected
    pw = PlaywrightFinding(login_forms_detected=True, password_fields=2)
    score = scorer._score_playwright(pw)
    assert score > 50

def test_combined_scoring():
    """Test combined risk score calculation"""
    scorer = RiskScorer()
    
    # Safe URL
    findings = ScanFindings(
        virustotal=VirusTotalFinding(detection_count=0, undetected_count=50, suspicious_count=0),
        urlscan=URLScanFinding(redirect_chain=[]),
        playwright=PlaywrightFinding(login_forms_detected=False, password_fields=0)
    )
    score, reason = scorer.calculate_score(findings)
    assert 0 <= score <= 30
    
    # Malicious URL
    findings = ScanFindings(
        virustotal=VirusTotalFinding(detection_count=20, undetected_count=0, suspicious_count=0),
        urlscan=URLScanFinding(redirect_chain=["a", "b", "c"]),
        playwright=PlaywrightFinding(login_forms_detected=True, password_fields=3)
    )
    score, reason = scorer.calculate_score(findings)
    assert score > 70

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
