"""Risk scoring logic combining signals from all three scanners"""
import logging
from models import ScanFindings

logger = logging.getLogger(__name__)

class RiskScorer:
    """Combines VirusTotal, URLScan, and Playwright signals into unified threat score"""
    
    def __init__(self, vt_weight: float = 0.35, urlscan_weight: float = 0.35, playwright_weight: float = 0.30):
        """
        Initialize scorer with weights.
        Weights should sum to 1.0.
        """
        self.vt_weight = vt_weight
        self.urlscan_weight = urlscan_weight
        self.playwright_weight = playwright_weight
        
        total = vt_weight + urlscan_weight + playwright_weight
        if abs(total - 1.0) > 0.01:
            logger.warning(f"Weights sum to {total}, not 1.0. Consider normalizing.")
    
    def calculate_score(self, findings: ScanFindings) -> tuple[int, str]:
        """
        Calculate combined threat score (0-100) and human-readable reason.
        
        Returns:
            (threat_score, reason_string)
        """
        scores = []
        reasons = []
        
        # VirusTotal score
        if findings.virustotal:
            vt_score = self._score_virustotal(findings.virustotal)
            scores.append((self.vt_weight, vt_score))
            if vt_score >= 60:
                reasons.append(f"VirusTotal: {findings.virustotal.detection_count} detections")
        
        # URLScan score
        if findings.urlscan:
            urlscan_score = self._score_urlscan(findings.urlscan)
            scores.append((self.urlscan_weight, urlscan_score))
            if urlscan_score >= 60:
                if findings.urlscan.redirect_chain:
                    reasons.append(f"URLScan: Redirects detected ({len(findings.urlscan.redirect_chain)} hops)")
                if findings.urlscan.http_status_code == 403 or findings.urlscan.http_status_code == 404:
                    reasons.append(f"URLScan: Suspicious HTTP {findings.urlscan.http_status_code}")
        
        # Playwright score
        if findings.playwright:
            playwright_score = self._score_playwright(findings.playwright)
            scores.append((self.playwright_weight, playwright_score))
            if playwright_score >= 60:
                if findings.playwright.login_forms_detected:
                    reasons.append("Credential form detected (phishing indicator)")
                if findings.playwright.suspicious_scripts:
                    reasons.append(f"Suspicious scripts: {len(findings.playwright.suspicious_scripts)}")
        
        # Calculate weighted average
        if not scores:
            threat_score = 0
            reason = "No scan data available"
        else:
            total_weight = sum(w for w, _ in scores)
            weighted_sum = sum(w * s for w, s in scores)
            threat_score = int(weighted_sum / total_weight) if total_weight > 0 else 0
            
            # Cap at 100
            threat_score = min(100, max(0, threat_score))
            
            # Build reason string
            if reasons:
                reason = " | ".join(reasons)
            else:
                reason = "URL appears safe based on all checks"

                # After calculating weighted average, add this:
        if findings.virustotal and findings.virustotal.detection_count >= 5:
            threat_score = max(threat_score, 70)
        if findings.virustotal and findings.virustotal.detection_count >= 10:
            threat_score = max(threat_score, 85)
        
        return threat_score, reason
    
    def _score_virustotal(self, vt_finding) -> int:
        """Score VirusTotal findings (0-100)"""
        if not vt_finding:
            return 0
        
        detection_count = vt_finding.detection_count
        
        # Simple scoring based on detection count
        if detection_count >= 10:
            return 95
        elif detection_count >= 5:
            return 80
        elif detection_count >= 2:
            return 60
        elif detection_count >= 1:
            return 40
        else:
            return 5  # Slight score even if no detections (could be new threat)
    
    def _score_urlscan(self, urlscan_finding) -> int:
        """Score URLScan.io findings (0-100)"""
        if not urlscan_finding:
            return 0
        
        score = 10  # Base score
        
        # Redirects increase risk
        if urlscan_finding.redirect_chain and len(urlscan_finding.redirect_chain) > 3:
            score += 40
        elif urlscan_finding.redirect_chain and len(urlscan_finding.redirect_chain) > 1:
            score += 25
        
        # Suspicious HTTP status codes
        if urlscan_finding.http_status_code and urlscan_finding.http_status_code >= 400:
            score += 20
        
        # Domain mismatch (original vs final)
        if urlscan_finding.final_url and urlscan_finding.final_url != urlscan_finding.page_domain:
            score += 15
        
        # Ads/trackers
        if urlscan_finding.ads and len(urlscan_finding.ads) > 3:
            score += 5
        
        return min(100, score)
    
    def _score_playwright(self, playwright_finding) -> int:
        """Score Playwright browser analysis findings (0-100)"""
        if not playwright_finding:
            return 0
        
        score = 10  # Base score
        
        # Login forms are high-risk indicator
        if playwright_finding.login_forms_detected:
            score += 50
        
        # Password fields
        score += min(20, playwright_finding.password_fields * 10)
        
        # Suspicious scripts
        if playwright_finding.suspicious_scripts:
            score += min(15, len(playwright_finding.suspicious_scripts) * 3)
        
        # External requests (potential exfiltration)
        if playwright_finding.external_requests and len(playwright_finding.external_requests) > 5:
            score += 10
        
        # Navigation/redirects at browser level
        if playwright_finding.redirect_count > 2:
            score += 10
        
        # Errors suggest evasion
        if playwright_finding.errors:
            score += 5
        
        return min(100, score)
