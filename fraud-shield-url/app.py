"""URL Sandbox - FastAPI main application"""
import logging
import asyncio
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from models import (
    ScanRequest, ScanResponse, ScanFindings,
    VirusTotalFinding, URLScanFinding, PlaywrightFinding,
)
from config import settings
from scanners.virustotal import VirusTotalScanner
from scanners.urlscan import URLScanScanner
from scanners.playwright_scanner import PlaywrightScanner
from scoring import RiskScorer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_model(value, model_cls):
    """Convert a scanner result to the expected Pydantic model.

    Handles three cases:
      - Already the correct model instance → pass through
      - A dict → construct the model from the dict
      - None or anything else → return None
    """
    if value is None:
        return None
    if isinstance(value, model_cls):
        return value
    if isinstance(value, dict):
        try:
            return model_cls(**value)
        except Exception as exc:
            logger.warning("Could not coerce dict to %s: %s", model_cls.__name__, exc)
            return None
    logger.warning("Unexpected scanner result type %s for %s", type(value).__name__, model_cls.__name__)
    return None


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("URL Sandbox starting up...")
    yield
    logger.info("URL Sandbox shutting down...")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Fraud Shield AI - URL Sandbox",
    description="Real-time behavioral URL analysis and threat scoring",
    version="0.2.0",
    lifespan=lifespan,
)

# Initialize scanners and scorer
vt_scanner = VirusTotalScanner(api_key=settings.virustotal_api_key)
urlscan_scanner = URLScanScanner(api_key=settings.urlscan_api_key)
playwright_scanner = PlaywrightScanner()
risk_scorer = RiskScorer(
    vt_weight=settings.vt_weight,
    urlscan_weight=settings.urlscan_weight,
    playwright_weight=settings.playwright_weight,
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "url-sandbox",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/scan-url", response_model=ScanResponse)
async def scan_url(request: ScanRequest) -> ScanResponse:
    """Scan a URL for phishing and malicious behavior.  Runs scanners in parallel."""
    scan_id = str(uuid.uuid4())
    url_str = str(request.url)

    logger.info("Starting scan %s for URL: %s", scan_id, url_str)

    try:
        # Run all three scanners in parallel
        vt_result, urlscan_result, playwright_result = await asyncio.gather(
            vt_scanner.scan(url_str),
            urlscan_scanner.scan(url_str),
            playwright_scanner.scan(
                url_str,
                timeout=request.timeout_override or settings.playwright_timeout,
            ),
            return_exceptions=True,
        )

        # Collect warnings for any scanner that raised
        warnings: list[str] = []

        if isinstance(vt_result, Exception):
            logger.error("VirusTotal failed: %s", vt_result)
            warnings.append(f"VirusTotal unavailable: {vt_result}")
            vt_result = None
        if isinstance(urlscan_result, Exception):
            logger.error("URLScan failed: %s", urlscan_result)
            warnings.append(f"URLScan unavailable: {urlscan_result}")
            urlscan_result = None
        if isinstance(playwright_result, Exception):
            logger.error("Playwright failed: %s", playwright_result)
            warnings.append(f"Playwright unavailable: {playwright_result}")
            playwright_result = None

        # Convert to model instances (handles dict / model / None)
        findings = ScanFindings(
            virustotal=_to_model(vt_result, VirusTotalFinding),
            urlscan=_to_model(urlscan_result, URLScanFinding),
            playwright=_to_model(playwright_result, PlaywrightFinding),
        )

        # Log which scanners produced data
        active = [
            name for name, val in [
                ("VT", findings.virustotal),
                ("URLScan", findings.urlscan),
                ("Playwright", findings.playwright),
            ] if val is not None
        ]
        logger.info("Findings built — active scanners: %s", ", ".join(active) or "none")

        # Calculate risk score
        threat_score, reason = risk_scorer.calculate_score(findings)

        response = ScanResponse(
            scan_id=scan_id,
            url=url_str,
            threat_score=threat_score,
            reason=reason,
            findings=findings,
            timestamp=datetime.now(timezone.utc),
            warnings=warnings,
        )

        logger.info("Scan %s complete — Score: %d/100", scan_id, threat_score)
        return response

    except Exception as e:
        logger.error("Error scanning %s: %s", url_str, e)
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")


@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "Fraud Shield AI - URL Sandbox",
        "version": "0.2.0",
        "endpoints": {
            "health": "/health",
            "scan": "/scan-url (POST)",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
