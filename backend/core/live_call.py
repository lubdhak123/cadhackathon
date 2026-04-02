"""
Live Call Analysis – WebSocket-based real-time scam detection
─────────────────────────────────────────────────────────────
Architecture:
  Browser mic → 5s audio chunks → WebSocket → RiskState → push score back

RiskState persists across chunks for the entire call duration.
Every chunk triggers all 3 layers; score accumulates with sliding window.
Alert fires when score crosses 80.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional
from detectors.voice_detector import acoustic_analysis, nlp_on_transcript, deepfake_detection, transcribe


# ── Intent progression ladder ────────────────────────────────────────────────
# As these intents appear in order, risk escalates
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

    @property
    def current_score(self) -> float:
        if not self.chunk_scores:
            return 0.0
        # Weighted average — recent chunks count more
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
            "transcript_so_far": self.transcript_so_far[-500:],  # last 500 chars
            "intent_progression": self.intent_progression,
            "deepfake_locked": self.deepfake_locked,
            "alert": score >= 80 and not self.alert_fired,
            "reasons": self.all_reasons[-8:],  # last 8 reasons
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


# ── In-memory store of active calls ─────────────────────────────────────────
_active_calls: dict[str, RiskState] = {}


def get_or_create_call(call_id: str) -> RiskState:
    if call_id not in _active_calls:
        _active_calls[call_id] = RiskState(call_id=call_id)
    return _active_calls[call_id]


def end_call(call_id: str) -> Optional[RiskState]:
    return _active_calls.pop(call_id, None)


# ── Process one audio chunk ──────────────────────────────────────────────────
def process_chunk(call_id: str, audio_bytes: bytes, vector_db=None) -> dict:
    """
    Process a single 5s audio chunk and update the RiskState.
    Returns the full updated state dict to push to frontend.
    """
    state = get_or_create_call(call_id)
    filename = "chunk.wav"

    chunk_reasons = []

    # Layer 1: Acoustic
    a_score, a_reasons = acoustic_analysis(audio_bytes, filename)
    chunk_reasons.extend(a_reasons)

    # Layer 2: Transcribe + NLP
    transcript = transcribe(audio_bytes, filename)
    if transcript:
        state.transcript_so_far = (state.transcript_so_far + " " + transcript).strip()

    n_score, n_reasons = nlp_on_transcript(state.transcript_so_far, vector_db)
    chunk_reasons.extend(n_reasons)

    # Extract intent from NLP reasons and track progression
    for reason in n_reasons:
        if reason.startswith("[NLP]"):
            # Extract intent label e.g. "[NLP] Banking Fraud: ..."
            parts = reason.split(":", 1)
            intent = parts[0].replace("[NLP]", "").strip().lower().replace(" ", "_")
            if intent and intent not in state.intent_progression:
                state.intent_progression.append(intent)

    # Layer 3: Deepfake
    d_score, d_reasons = deepfake_detection(audio_bytes, filename)
    chunk_reasons.extend(d_reasons)

    # Lock deepfake if single chunk is highly confident
    if d_score > 70:
        state.deepfake_locked = True
        chunk_reasons.insert(0, "DEEPFAKE LOCKED: AI voice clone detected on this chunk")

    # Weighted chunk score
    chunk_final = (a_score * 0.25) + (n_score * 0.45) + (d_score * 0.30)
    if state.deepfake_locked:
        chunk_final = max(chunk_final, 85.0)

    state.chunk_scores.append(chunk_final)
    state.all_reasons.extend(chunk_reasons)

    result = state.to_dict()

    # Mark alert as fired so we don't re-fire
    if result["alert"]:
        state.alert_fired = True

    return result
