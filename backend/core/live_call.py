"""
Live Call Analysis – WebSocket-based real-time scam detection
─────────────────────────────────────────────────────────────
Fixes applied:
  Fix 1: Groq NLP runs async — doesn't block chunk pipeline
  Fix 2: Whisper 'tiny' model for live calls (faster)
  Fix 4: Partial phrase matching on rolling transcript
  Fix 5: ABNORMAL_CLOSURE handled as normal close
"""

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import List, Optional
from detectors.voice_detector import acoustic_analysis, deepfake_detection, URGENCY_PHRASES, nlp_on_transcript


# ── Intent progression ladder ────────────────────────────────────────────────
PROGRESSION_LADDER = [
    "identity_verification",
    "security_threat",
    "action_required",
    "credential_harvesting",
    "government_impersonation",
    "banking_fraud",
    "family_emergency_impersonation",
]


@dataclass
class RiskState:
    call_id: str
    started_at: float = field(default_factory=time.time)
    chunk_scores: List[float] = field(default_factory=list)
    transcript_so_far: str = ""
    intent_progression: List[str] = field(default_factory=list)
    deepfake_locked: bool = False
    alert_fired: bool = False
    all_reasons: List[str] = field(default_factory=list)
    pending_nlp_score: float = 0.0  # Fix 1: async NLP result stored here

    @property
    def current_score(self) -> float:
        if not self.chunk_scores:
            return 0.0
        n = len(self.chunk_scores)
        weights = list(range(1, n + 1))
        weighted = sum(s * w for s, w in zip(self.chunk_scores, weights))
        return min(100.0, weighted / sum(weights))

    @property
    def duration_seconds(self) -> float:
        return time.time() - self.started_at

    def to_dict(self) -> dict:
        score = self.current_score
        return {
            "call_id": self.call_id,
            "current_score": round(score, 1),
            "verdict": _verdict(score),
            "severity": _severity(score),
            "chunk_count": len(self.chunk_scores),
            "duration_seconds": round(self.duration_seconds, 1),
            "transcript_so_far": self.transcript_so_far[-500:],
            "intent_progression": self.intent_progression,
            "deepfake_locked": self.deepfake_locked,
            "alert": score >= 80 and not self.alert_fired,
            "reasons": self.all_reasons[-8:],
        }


def _verdict(score: float) -> str:
    if score >= 80: return "SCAM"
    if score >= 55: return "SUSPICIOUS"
    if score >= 35: return "UNCERTAIN"
    return "SAFE"


def _severity(score: float) -> str:
    if score >= 80: return "HIGH"
    if score >= 55: return "MEDIUM"
    if score >= 35: return "LOW"
    return "NONE"


# ── In-memory store ──────────────────────────────────────────────────────────
_active_calls: dict[str, RiskState] = {}


def get_or_create_call(call_id: str) -> RiskState:
    if call_id not in _active_calls:
        _active_calls[call_id] = RiskState(call_id=call_id)
    return _active_calls[call_id]


def end_call(call_id: str) -> Optional[RiskState]:
    return _active_calls.pop(call_id, None)


# ── Fix 2: Fast transcription for live calls using tiny model ────────────────
def transcribe_fast(audio_bytes: bytes, filename: str) -> str:
    """Use Whisper tiny model for live call speed."""
    import tempfile
    try:
        from faster_whisper import WhisperModel
        suffix = os.path.splitext(filename)[-1] or ".wav"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        # Fix 2: tiny model is 4x faster than base
        model = WhisperModel("tiny", device="cpu", compute_type="int8")
        segments, info = model.transcribe(tmp_path, language=None)
        transcript = " ".join(s.text for s in segments)
        # Fix 3: translate Hindi/Urdu to English
        if info.language in ("hi", "ur", "pa"):
            segments2, _ = model.transcribe(tmp_path, language=info.language, task="translate")
            transcript = " ".join(s.text for s in segments2)
        os.unlink(tmp_path)
        return transcript.strip()
    except Exception as e:
        return ""


# ── Fix 4: Keyword scoring on rolling transcript ─────────────────────────────
def keyword_score_rolling(transcript: str, vector_db=None) -> tuple[float, list[str]]:
    """Fix 4: Run nlp_on_transcript on full rolling transcript for better coverage."""
    return nlp_on_transcript(transcript, vector_db)


# ── Fix 1: Async Groq NLP ────────────────────────────────────────────────────
async def run_nlp_async(state: RiskState):
    """
    Run Groq NLP in background — doesn't block chunk processing.
    Updates state.pending_nlp_score when done.
    """
    import json
    from detectors.voice_detector import VOICE_NLP_SYSTEM, scrub_pii
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key or not state.transcript_so_far:
        return
    try:
        from groq import Groq
        client = Groq(api_key=groq_key)
        safe = scrub_pii(state.transcript_so_far[-1000:])
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=200,
            messages=[
                {"role": "system", "content": VOICE_NLP_SYSTEM},
                {"role": "user", "content": f"Analyze this call transcript:\n\n{safe}"},
            ],
        )
        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
            raw = raw.rsplit("```", 1)[0]
        data = json.loads(raw)
        nlp_conf = float(data.get("confidence", 0))
        state.pending_nlp_score = min(40, nlp_conf * 0.5)
        intent = data.get("intent", "unknown")
        reasoning = data.get("reasoning", "")
        if data.get("is_scam") or nlp_conf > 30:
            state.all_reasons.append(f"[NLP] {intent.replace('_',' ').title()}: {reasoning}")
            if intent not in state.intent_progression:
                state.intent_progression.append(intent)
    except Exception as e:
        pass


# ── Process one audio chunk ──────────────────────────────────────────────────
def process_chunk(call_id: str, audio_bytes: bytes, vector_db=None) -> dict:
    state = get_or_create_call(call_id)
    filename = "chunk.wav"
    chunk_reasons = []

    # Layer 1: Acoustic (fast)
    a_score, a_reasons = acoustic_analysis(audio_bytes, filename)
    chunk_reasons.extend(a_reasons)

    # Layer 2: Fix 2 — fast transcription
    transcript = transcribe_fast(audio_bytes, filename)
    if transcript:
        state.transcript_so_far = (state.transcript_so_far + " " + transcript).strip()

    # Fix 4: keyword scoring on full rolling transcript
    k_score, k_reasons = keyword_score_rolling(state.transcript_so_far, vector_db)
    chunk_reasons.extend(k_reasons)

    # Fix 1: include pending NLP score from previous async call
    nlp_bonus = state.pending_nlp_score
    n_score = min(85.0, k_score + nlp_bonus)

    # Fire async NLP for next chunk (non-blocking)
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(run_nlp_async(state))
    except Exception:
        pass

    # Layer 3: Deepfake (fast on 5s chunk)
    d_score, d_reasons = deepfake_detection(audio_bytes, filename)
    chunk_reasons.extend(d_reasons)

    if d_score > 70:
        state.deepfake_locked = True
        chunk_reasons.insert(0, "DEEPFAKE LOCKED: AI voice clone detected")

    chunk_final = (a_score * 0.25) + (n_score * 0.45) + (d_score * 0.30)
    if state.deepfake_locked:
        chunk_final = max(chunk_final, 85.0)

    state.chunk_scores.append(chunk_final)
    state.all_reasons.extend(chunk_reasons)

    result = state.to_dict()
    if result["alert"]:
        state.alert_fired = True

    return result
