"""
Voice Detector – Enhanced Real-Time Call Analysis
──────────────────────────────────────────────────
Three-layer pipeline:
  1. Acoustic analysis      (librosa) – tone, pitch, energy, speaking rate
  2. Speech-to-Text + NLP   (Whisper + keyword detection)
  3. Deepfake detection      (spectral analysis for synthetic voice markers)
"""

import os
import io
import tempfile
from typing import Dict, Any, List, Tuple

from core.threat_score import ThreatScore


# ── Layer 1: Acoustic Analysis ──────────────────────────────────────────────

def acoustic_analysis(audio_bytes: bytes, filename: str) -> Tuple[float, List[str]]:
    try:
        import librosa
        import numpy as np
    except ImportError:
        return 0.0, ["librosa not installed – acoustic analysis skipped"]

    reasons = []
    score = 0.0

    try:
        suffix = os.path.splitext(filename)[-1] or ".wav"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name

        y, sr = librosa.load(tmp_path, sr=None, mono=True)
        os.unlink(tmp_path)
        duration = librosa.get_duration(y=y, sr=sr)

        # Pitch variance – rapid changes = agitation / pressure
        pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
        pitch_vals = pitches[magnitudes > magnitudes.mean()]
        if len(pitch_vals) > 0:
            pitch_std = float(pitch_vals.std())
            pitch_mean = float(pitch_vals[pitch_vals > 0].mean()) if (pitch_vals > 0).any() else 0
            if pitch_std > 80:
                score += 15
                reasons.append(f"High pitch variance ({pitch_std:.0f} Hz) – emotional agitation")
            if pitch_mean > 300:
                score += 10
                reasons.append(f"Elevated average pitch ({pitch_mean:.0f} Hz) – possible stress/deception")

        # Speaking rate
        tempo, _ = librosa.beat.beat_track(y=y, sr=sr)
        if tempo > 150:
            score += 10
            reasons.append(f"Fast speaking rate (tempo {tempo:.0f} BPM) – scripted call pattern")

        # RMS energy – shouting / pressure
        rms = librosa.feature.rms(y=y)[0]
        rms_std = float(rms.std())
        rms_mean = float(rms.mean())
        if rms_mean > 0 and rms_std / rms_mean > 0.8:
            score += 10
            reasons.append("High energy variance – shouting/pressure pattern")

        # Silence ratio – scripted calls have little silence
        silent_frames = (rms < 0.01).sum()
        silence_ratio = silent_frames / max(len(rms), 1)
        if silence_ratio < 0.05 and duration > 10:
            score += 10
            reasons.append("Very low silence ratio – automated/scripted call")

    except Exception as e:
        reasons.append(f"Acoustic error: {str(e)[:80]}")

    return min(score, 50.0), reasons


# ── Layer 2: Speech-to-Text + NLP ───────────────────────────────────────────

SCAM_PHRASES = [
    "otp", "one time password", "share your otp", "verify your account",
    "bank account", "credit card", "debit card", "cvv", "pin number",
    "arrested", "police", "legal action", "income tax", "aadhaar",
    "transfer money", "send money", "remote access", "teamviewer", "anydesk",
    "lottery", "prize", "won", "lucky draw", "customs", "parcel",
    "kyc", "update kyc", "suspended", "blocked", "expire",
    "government scheme", "subsidy", "refund", "insurance claim",
    "social security", "warrant", "fraud department",
]

URGENCY_PHRASES = [
    "immediately", "urgent", "right now", "quickly", "hurry", "within one hour",
    "last chance", "don't hang up", "stay on the line",
]


def transcribe(audio_bytes: bytes, filename: str) -> str:
    # Try local faster-whisper first
    try:
        from faster_whisper import WhisperModel
        suffix = os.path.splitext(filename)[-1] or ".wav"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        model = WhisperModel("tiny", device="cpu", compute_type="int8")
        segments, _ = model.transcribe(tmp_path, language="en")
        os.unlink(tmp_path)
        return " ".join(s.text for s in segments)
    except ImportError:
        pass

    # Fallback: OpenAI Whisper API
    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        try:
            import openai
            client = openai.OpenAI(api_key=openai_key)
            buf = io.BytesIO(audio_bytes)
            buf.name = filename
            result = client.audio.transcriptions.create(model="whisper-1", file=buf)
            return result.text
        except Exception:
            pass

    return ""


def nlp_on_transcript(transcript: str) -> Tuple[float, List[str]]:
    if not transcript:
        return 0.0, ["Could not transcribe audio"]

    lower = transcript.lower()
    reasons = []
    score = 0.0

    hits = [p for p in SCAM_PHRASES if p in lower]
    if hits:
        score += min(60, len(hits) * 9)
        reasons.append(f"Scam phrases: {', '.join(hits[:5])}")

    u_hits = [w for w in URGENCY_PHRASES if w in lower]
    if u_hits:
        score += min(20, len(u_hits) * 7)
        reasons.append(f"Urgency pressure: {', '.join(u_hits[:3])}")

    return min(score, 80.0), reasons


# ── Layer 3: Deepfake Voice Detection ───────────────────────────────────────

def deepfake_detection(audio_bytes: bytes, filename: str) -> Tuple[float, List[str]]:
    """
    Spectral analysis for synthetic voice markers:
    - AI voices have unnaturally smooth spectral envelopes
    - Missing micro-variations in formant frequencies
    - Consistent F0 (fundamental frequency) without natural jitter
    """
    try:
        import librosa
        import numpy as np
    except ImportError:
        return 0.0, ["librosa not installed – deepfake detection skipped"]

    reasons = []
    score = 0.0

    try:
        suffix = os.path.splitext(filename)[-1] or ".wav"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name

        y, sr = librosa.load(tmp_path, sr=None, mono=True)
        os.unlink(tmp_path)

        # Spectral flatness – synthetic voices tend to have higher spectral flatness
        flatness = librosa.feature.spectral_flatness(y=y)[0]
        mean_flatness = float(flatness.mean())
        if mean_flatness > 0.15:
            score += 25
            reasons.append(f"High spectral flatness ({mean_flatness:.3f}) – possible synthetic voice")

        # Zero-crossing rate – AI voices may have lower jitter
        zcr = librosa.feature.zero_crossing_rate(y)[0]
        zcr_std = float(zcr.std())
        if zcr_std < 0.01:
            score += 20
            reasons.append("Unnaturally consistent zero-crossing rate – deepfake indicator")

        # Mel-frequency cepstral coefficient (MFCC) variance
        mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
        mfcc_var = float(mfccs.var(axis=1).mean())
        if mfcc_var < 10:
            score += 20
            reasons.append(f"Low MFCC variance ({mfcc_var:.1f}) – lacks natural speech texture")

        # F0 jitter – natural voices have small random pitch variations
        f0, voiced_flag, voiced_probs = librosa.pyin(y, fmin=librosa.note_to_hz('C2'), fmax=librosa.note_to_hz('C7'))
        f0_clean = f0[~np.isnan(f0)]
        if len(f0_clean) > 10:
            jitter = float(np.diff(f0_clean).std())
            if jitter < 2.0:
                score += 20
                reasons.append(f"Very low F0 jitter ({jitter:.2f} Hz) – unnaturally stable pitch (deepfake marker)")

    except Exception as e:
        reasons.append(f"Deepfake detection error: {str(e)[:80]}")

    return min(score, 70.0), reasons


# ── Main Detector ───────────────────────────────────────────────────────────

class VoiceDetector:
    def analyze(self, audio_bytes: bytes, filename: str) -> Dict[str, Any]:
        reasons = []

        # Layer 1 – Acoustics
        a_score, a_reasons = acoustic_analysis(audio_bytes, filename)
        reasons.extend(a_reasons)

        # Layer 2 – Transcript NLP
        transcript = transcribe(audio_bytes, filename)
        n_score, n_reasons = nlp_on_transcript(transcript)
        reasons.extend(n_reasons)

        # Layer 3 – Deepfake detection
        d_score, d_reasons = deepfake_detection(audio_bytes, filename)
        reasons.extend(d_reasons)

        final = (a_score * 0.25) + (n_score * 0.45) + (d_score * 0.30)

        return ThreatScore.build(
            score=final,
            reasons=reasons,
            source="voice",
            raw={
                "transcript": transcript[:500] if transcript else "",
                "acoustic_score": round(a_score, 1),
                "nlp_score": round(n_score, 1),
                "deepfake_score": round(d_score, 1),
                "is_deepfake": d_score > 40,
            },
        )
