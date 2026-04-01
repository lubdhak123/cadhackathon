"""
Fraud Shield AI – Unified Scam Detection API
═════════════════════════════════════════════
Best of Zora AI + Fraud Shield combined.
Multi-source input → Central Classifier → Risk Scoring → Human Feedback Loop
"""

import uuid
from contextlib import asynccontextmanager
from dotenv import load_dotenv
load_dotenv()

import uvicorn
from fastapi import FastAPI, Request, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from middleware.shadow_guard import ShadowGuardMiddleware
from middleware.dlp_guard import DLPGuardMiddleware
from core.vector_db import VectorDB
from core.classifier import CentralClassifier
from core.feedback import FeedbackStore
from core.threat_score import ThreatScore
from detectors.text_detector import TextDetector
from detectors.credential_detector import CredentialDetector
from detectors.url_detector import URLDetector
from detectors.voice_detector import VoiceDetector
from detectors.file_detector import FileDetector
from detectors.email_detector import EmailDetector, IMAPFetcher
from detectors.video_detector import VideoDetector


# ── Startup ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.vector_db = VectorDB()
    app.state.vector_db.seed_known_scams()
    app.state.feedback = FeedbackStore()
    yield


# ── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Fraud Shield AI",
    description="Unified scam detection: SMS, Email, URL, Voice, Files — with deepfake detection, DLP, and human-in-the-loop feedback",
    version="2.0.0",
    lifespan=lifespan,
)

# Middleware stack (order matters – outermost first)
app.add_middleware(DLPGuardMiddleware)
app.add_middleware(ShadowGuardMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ──────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "name": "Fraud Shield AI",
        "version": "2.0.0",
        "status": "running",
        "detectors": ["text", "credential", "url", "voice", "file", "email"],
        "middleware": ["shadow_guard", "dlp_guard"],
        "features": ["deepfake_detection", "ai_generated_text_detection", "human_feedback", "imap_integration"],
    }


# ── Individual Detectors ────────────────────────────────────────────────────

@app.post("/analyze/text")
async def analyze_text(
    message: str = Form(...),
    sender: str = Form(default="unknown"),
    channel: str = Form(default="sms"),
):
    """Analyze SMS or Email body for scam indicators."""
    detector = TextDetector(app.state.vector_db)
    text_result = detector.analyze(message, sender, channel)

    cred_detector = CredentialDetector()
    cred_result = cred_detector.analyze(message)

    combined = ThreatScore.combine({"text": text_result, "credential": cred_result})
    return {
        "analysis_id": str(uuid.uuid4())[:8],
        "components": {"text": text_result, "credential": cred_result},
        "combined": combined,
    }


@app.post("/analyze/url")
async def analyze_url(url: str = Form(...)):
    """Sandbox + SSL + WHOIS + heuristic URL analysis."""
    detector = URLDetector()
    result = await detector.analyze(url)
    result["analysis_id"] = str(uuid.uuid4())[:8]
    return result


@app.post("/analyze/voice")
async def analyze_voice(request: Request, audio: UploadFile = File(...)):
    """Acoustic + STT + deepfake voice analysis."""
    audio_bytes = await audio.read()
    detector = VoiceDetector(vector_db=request.app.state.vector_db)
    result = detector.analyze(audio_bytes, audio.filename)
    result["analysis_id"] = str(uuid.uuid4())[:8]
    return result


@app.post("/analyze/video")
async def analyze_video(video: UploadFile = File(...)):
    """Video deepfake detection — temporal consistency + facial artifacts + AV sync."""
    video_bytes = await video.read()
    detector = VideoDetector()
    result = detector.analyze(video_bytes, video.filename)
    result["analysis_id"] = str(uuid.uuid4())[:8]
    return result


@app.post("/analyze/file")
async def analyze_file(attachment: UploadFile = File(...)):
    """YARA + ClamAV/VirusTotal file scan."""
    file_bytes = await attachment.read()
    detector = FileDetector()
    result = detector.analyze(file_bytes, attachment.filename)
    result["analysis_id"] = str(uuid.uuid4())[:8]
    return result


@app.post("/analyze/email")
async def analyze_email(
    raw_email: str = Form(default=""),
    body: str = Form(default=""),
    sender: str = Form(default="unknown"),
):
    """Analyze email headers (SPF/DKIM/DMARC) + body."""
    detector = EmailDetector()
    if raw_email:
        result = detector.analyze_raw(raw_email)
    else:
        result = detector.analyze_body(body, sender)
    result["analysis_id"] = str(uuid.uuid4())[:8]
    return result


# ── Full Analysis (Central Classifier) ──────────────────────────────────────

@app.post("/analyze/full")
async def analyze_full(
    message: str = Form(default=""),
    sender: str = Form(default="unknown"),
    channel: str = Form(default="sms"),
    url: str = Form(default=""),
    audio: UploadFile = File(default=None),
    attachment: UploadFile = File(default=None),
):
    """Run ALL available detectors and return a combined threat assessment."""
    classifier = CentralClassifier(app.state.vector_db)
    result = await classifier.classify(
        message=message,
        sender=sender,
        channel=channel,
        url=url,
        audio_bytes=(await audio.read()) if audio else None,
        audio_filename=audio.filename if audio else "",
        file_bytes=(await attachment.read()) if attachment else None,
        file_filename=attachment.filename if attachment else "",
    )
    result["analysis_id"] = str(uuid.uuid4())[:8]
    return result


# ── IMAP Email Scanning ─────────────────────────────────────────────────────

@app.post("/email/scan-inbox")
async def scan_inbox(
    imap_host: str = Form(...),
    email_addr: str = Form(...),
    password: str = Form(...),
    count: int = Form(default=10),
):
    """Connect to IMAP inbox and scan recent emails."""
    fetcher = IMAPFetcher(imap_host, email_addr, password)
    emails = fetcher.fetch_recent(count=count)
    detector = EmailDetector()
    text_det = TextDetector(app.state.vector_db)

    results = []
    for em in emails:
        if "error" in em:
            results.append(em)
            continue

        # Header analysis
        email_result = detector.analyze_raw(em.get("raw", ""))

        # Body text analysis
        body = em.get("body", "")
        text_result = text_det.analyze(body, em.get("from", "unknown"), "email") if body else None

        combined = ThreatScore.combine(
            {"email": email_result, **({"text": text_result} if text_result else {})}
        )

        results.append({
            "email_id": em.get("id"),
            "from": em.get("from"),
            "subject": em.get("subject"),
            "date": em.get("date"),
            "analysis": combined,
        })

    return {"emails_scanned": len(results), "results": results}


# ── Human-in-the-Loop Feedback ──────────────────────────────────────────────

@app.post("/feedback")
async def submit_feedback(
    analysis_id: str = Form(...),
    user_verdict: str = Form(...),  # "scam" | "safe" | "unsure"
    original_score: float = Form(default=0),
    original_verdict: str = Form(default=""),
    source: str = Form(default=""),
    original_input: str = Form(default=""),
    comment: str = Form(default=""),
):
    """Submit human feedback on an analysis result. Improves future accuracy."""
    entry = app.state.feedback.add_feedback(
        analysis_id=analysis_id,
        user_verdict=user_verdict,
        original_score=original_score,
        original_verdict=original_verdict,
        source=source,
        original_input=original_input,
        comment=comment,
    )

    # If user confirms it's a scam, add to vector DB for future matching
    if user_verdict == "scam" and original_input:
        app.state.vector_db.add_scam(original_input, reported_by="user_feedback")

    return {"status": "feedback recorded", "entry": entry}


@app.get("/feedback/stats")
async def feedback_stats():
    """Get accuracy statistics from user feedback."""
    return app.state.feedback.get_accuracy_stats()


@app.get("/feedback/recent")
async def recent_feedback(limit: int = Query(default=20)):
    """Get recent feedback entries."""
    return app.state.feedback.get_recent(limit=limit)


# ── Run ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
