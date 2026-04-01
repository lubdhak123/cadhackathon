"""
Voice Detector – Enhanced Real-Time Call Analysis
──────────────────────────────────────────────────
Three-layer pipeline:
  1. Acoustic analysis      (librosa) – tone, pitch, energy, boiler room noise
  2. Speech-to-Text + NLP   (Whisper + keyword + vector + Claude)
  3. Deepfake detection     (spectral physics — no dataset needed)

Extras:
  - GSM preprocessing       (normalize + resample before spectral analysis)
  - PII redaction           (scrub before sending transcript to Claude)
  - Deepfake override       (if deepfake score > 70 → force HIGH RISK)
  - Voice cloning detection (family impersonation via spectral envelope analysis)
"""

import os
import io
import re
import json
import tempfile
from typing import Dict, Any, List, Tuple

import anthropic

from core.threat_score import ThreatScore
from core.vector_db import VectorDB


# ── PII Scrubber (runs before transcript hits Claude) ───────────────────────

def scrub_pii(text: str) -> str:
    """Redact sensitive identifiers before sending to external LLM API."""
    text = re.sub(r'\b\d{12}\b', '[AADHAAR]', text)                     # Aadhaar
    text = re.sub(r'\b[A-Z]{5}\d{4}[A-Z]\b', '[PAN]', text)             # PAN card
    text = re.sub(r'\b\d{16}\b', '[CARD_NUMBER]', text)                  # Credit/debit card
    text = re.sub(r'\b\d{9,11}\b', '[PHONE]', text)                      # Phone numbers
    text = re.sub(r'\b\d{6}\b', '[OTP_OR_PIN]', text)                    # OTP / PIN
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL]', text)            # Email addresses
    text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                  '[CARD_NUMBER]', text)                                  # Card with spaces
    return text


# ── GSM Audio Preprocessor ──────────────────────────────────────────────────

def preprocess_audio(y, sr):
    """
    Normalize and resample audio for telephonic recordings.
    Phone calls use GSM codec — cuts frequencies above 3.4 kHz,
    which can cause false positives in MFCC/spectral flatness analysis.
    """
    try:
        import librosa
        import numpy as np
        # Normalize amplitude
        y = librosa.util.normalize(y)
        # Resample to 16kHz (standard for speech processing)
        if sr != 16000:
            y = librosa.resample(y, orig_sr=sr, target_sr=16000)
            sr = 16000
        return y, sr
    except Exception:
        return y, sr


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

        # Preprocess for telephonic audio
        y, sr = preprocess_audio(y, sr)
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
                reasons.append(f"Elevated average pitch ({pitch_mean:.0f} Hz) – stress indicator")

        # Speaking rate via onset detection (more accurate than beat_track for speech)
        onset_frames = librosa.onset.onset_detect(y=y, sr=sr)
        if duration > 0:
            syllable_rate = len(onset_frames) / duration
            if syllable_rate > 6.0:
                score += 10
                reasons.append(f"High speaking rate ({syllable_rate:.1f} syllables/sec) – scripted call pattern")

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

        # Boiler room background noise detection
        # Call centers have a characteristic ambient frequency profile (200-800 Hz band noise)
        if duration > 5:
            stft = np.abs(librosa.stft(y))
            freqs = librosa.fft_frequencies(sr=sr)
            boiler_band = stft[(freqs >= 200) & (freqs <= 800), :]
            background_band = stft[(freqs > 800), :]
            if background_band.mean() > 0:
                boiler_ratio = boiler_band.mean() / background_band.mean()
                if boiler_ratio > 2.5:
                    score += 15
                    reasons.append(
                        f"Background noise profile matches call center environment "
                        f"(boiler room ratio: {boiler_ratio:.1f})"
                    )

    except Exception as e:
        reasons.append(f"Acoustic error: {str(e)[:80]}")

    return min(score, 55.0), reasons


# ── Layer 2: Speech-to-Text + NLP ───────────────────────────────────────────

SCAM_PHRASES = [
    # English — banking / financial
    "otp", "one time password", "share your otp", "verify your account",
    "bank account", "credit card", "debit card", "cvv", "pin number",
    "arrested", "police", "legal action", "income tax", "aadhaar",
    "transfer money", "send money", "remote access", "teamviewer", "anydesk",
    "lottery", "prize", "won", "lucky draw", "customs", "parcel",
    "kyc", "update kyc", "suspended", "blocked", "expire",
    "government scheme", "subsidy", "refund", "insurance claim",
    "social security", "warrant", "fraud department",

    # English — family emergency / voice cloning scam
    "i'm in trouble", "i need help", "don't tell mom", "don't tell dad",
    "i had an accident", "i'm at the police station", "bail money",
    "new number", "lost my phone", "send money urgently", "i got arrested",
    "please don't tell anyone", "i'm in jail", "hospital emergency",

    # Hindi / Hinglish — banking
    "otp batao", "otp share karo", "otp bata do", "otp dena hoga",
    "aadhaar number do", "aadhaar card bhejo", "pan card number do",
    "account band ho jayega", "account block ho jayega", "account suspend ho jayega",
    "police aa jayegi", "police bhej denge", "arrest ho jaoge", "giraftari hogi",
    "court notice", "legal notice bheja hai", "case darj ho gaya",
    "kyc update karo", "kyc incomplete hai", "kyc verify karo",
    "paisa transfer karo", "paise bhejo", "turant transfer karo",
    "inaam mila hai", "lucky draw mein naam aaya", "inam jeeta hai",
    "customs department", "customs mein parcel hai", "cbdt notice",
    "rbi se call", "rbi bol raha hoon", "rbi ka notice",
    "sbi se bol raha hoon", "hdfc se call", "bank manager bol raha hoon",
    "sim band ho jayega", "number block ho jayega",
    "abhi karo warna", "ek ghante mein", "turant karo",
    "kisi ko mat batana", "call mat kato", "line pe raho",
    "ghar pe akele ho", "parivaar ko mat batana",
    "digital arrest", "cyber crime department",

    # Hindi / Hinglish — family emergency / voice cloning
    "main musibat mein hoon", "mujhe paison ki zaroorat hai",
    "accident ho gaya", "hospital mein hoon", "police station pe hoon",
    "bail chahiye", "naya number hai mera", "phone kho gaya",
    "kisi ko mat batana", "please help karo", "emergency hai",
    "ghar pe kisi ko mat batana", "abhi transfer karo",
]

URGENCY_PHRASES = [
    # English
    "immediately", "urgent", "right now", "quickly", "hurry", "within one hour",
    "last chance", "don't hang up", "stay on the line",
    # Hindi / Hinglish
    "abhi karo", "turant karo", "jaldi karo", "ek ghante mein",
    "aaj hi", "der mat karo", "phone mat katna", "line pe raho",
    "warna action liya jayega", "warna case hoga",
]


def transcribe(audio_bytes: bytes, filename: str) -> str:
    """Transcribe audio — multilingual (en + hi) for Hindi/Hinglish support."""
    try:
        from faster_whisper import WhisperModel
        suffix = os.path.splitext(filename)[-1] or ".wav"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = tmp.name
        # base model for better accuracy on Indian-accented English + Hindi
        model = WhisperModel("base", device="cpu", compute_type="int8")
        # language=None → auto-detect (handles Hindi, Hinglish, English)
        segments, _ = model.transcribe(tmp_path, language=None)
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


VOICE_NLP_SYSTEM = """You are a scam call detection engine. Analyze this phone call transcript and return ONLY valid JSON:
{
  "is_scam": true/false,
  "confidence": 0-100,
  "intent": "banking_fraud|government_impersonation|tech_support|kyc_scam|prize_scam|job_scam|family_emergency_impersonation|legitimate|unknown",
  "reasoning": "one sentence"
}
Focus on:
- Requests for OTP, passwords, card details, Aadhaar, PAN
- Impersonating banks, RBI, CBI, police, government departments
- Threats of arrest, account suspension, legal action
- Urgency pressure and isolation tactics (don't tell anyone)
- Family emergency claims + urgent money requests (voice cloning pattern)
- Caller claims to be a family member from a new number in distress"""


def nlp_on_transcript(transcript: str, vector_db: VectorDB = None) -> Tuple[float, List[str]]:
    if not transcript:
        return 0.0, ["Could not transcribe audio"]

    lower = transcript.lower()
    reasons = []
    score = 0.0

    # ── Keyword baseline with urgency multiplier ────────────────────────────
    # Weighted scores per keyword — higher risk phrases score more
    SCAM_WEIGHTS = {
        "otp": 40, "one time password": 40, "share your otp": 40,
        "cvv": 35, "aadhaar": 35, "aadhar": 35, "pan card": 30,
        "anydesk": 30, "teamviewer": 30, "remote access": 30,
        "pin number": 25, "screen share": 25,
        "bank account": 20, "credit card": 20, "debit card": 20,
        "password": 20, "arrested": 20, "digital arrest": 20,
        "police": 15, "verify": 15, "blocked": 15, "suspended": 15,
        "refund": 10, "kyc": 15, "warrant": 20,
    }

    has_urgency = any(u in lower for u in URGENCY_PHRASES)
    # 1.5x multiplier on all scam scores if urgency is present
    urgency_multiplier = 1.5 if has_urgency else 1.0

    keyword_score = 0
    keyword_hits = []
    for phrase, base in SCAM_WEIGHTS.items():
        if phrase in lower:
            awarded = int(base * urgency_multiplier)
            keyword_score += awarded
            keyword_hits.append(f"{phrase}(+{awarded})")

    # Also catch any phrases not in weighted dict
    extra_hits = [p for p in SCAM_PHRASES if p not in SCAM_WEIGHTS and p in lower]
    if extra_hits:
        extra = int(8 * urgency_multiplier)
        keyword_score += len(extra_hits) * extra
        keyword_hits.extend(extra_hits[:3])

    if keyword_hits:
        score += min(45, keyword_score)
        reasons.append(f"Scam phrases detected: {', '.join(keyword_hits[:5])}")

    if has_urgency:
        u_hits = [w for w in URGENCY_PHRASES if w in lower]
        score += min(15, len(u_hits) * 5)
        reasons.append(f"Urgency pressure (1.5x multiplier active): {', '.join(u_hits[:3])}")

    # ── Vector DB similarity ────────────────────────────────────────────────
    if vector_db:
        try:
            similar = vector_db.query_similarity(transcript, n_results=3)
            if similar:
                top = similar[0]
                sim_pct = top["similarity_pct"]
                if sim_pct > 55:
                    score += min(30, sim_pct * 0.4)
                    reasons.append(
                        f"Matches known scam transcript ({sim_pct:.0f}% similar): "
                        f"\"{top['template'][:60]}...\""
                    )
        except Exception:
            pass

    # ── PII scrub before sending to Claude ─────────────────────────────────
    safe_transcript = scrub_pii(transcript[:1000])

    # ── Claude Haiku intent classification ──────────────────────────────────
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        try:
            client = anthropic.Anthropic(api_key=api_key)
            resp = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=200,
                system=VOICE_NLP_SYSTEM,
                messages=[{"role": "user", "content": f"Analyze this call transcript:\n\n{safe_transcript}"}],
            )
            data = json.loads(resp.content[0].text)
            if data.get("is_scam"):
                nlp_score = float(data.get("confidence", 0))
                score += min(30, nlp_score * 0.3)
                intent = data.get("intent", "unknown")
                reasoning = data.get("reasoning", "")
                reasons.append(f"[NLP] {intent.replace('_', ' ').title()}: {reasoning}")
        except Exception as e:
            reasons.append(f"NLP skipped: {str(e)[:60]}")

    return min(score, 85.0), reasons


# ── Layer 3: Deepfake Voice Detection ───────────────────────────────────────

def deepfake_detection(audio_bytes: bytes, filename: str) -> Tuple[float, List[str]]:
    """
    Spectral physics analysis — no training dataset needed.
    AI/cloned voices physically cannot replicate:
    - Natural spectral noise (spectral flatness)
    - Micro pitch instability (F0 jitter)
    - Chaotic speech texture (MFCC variance)
    - Natural zero-crossing fluctuation (ZCR std)

    Also catches voice cloning (3-second clone):
    - Cloned voices have overly consistent spectral envelopes
    - Lack the natural pitch shifts a distressed real person would have
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

        # Preprocess to avoid false positives from GSM compression
        y, sr = preprocess_audio(y, sr)

        # Spectral flatness – AI voices are too spectrally smooth
        flatness = librosa.feature.spectral_flatness(y=y)[0]
        mean_flatness = float(flatness.mean())
        if mean_flatness > 0.15:
            score += 25
            reasons.append(
                f"High spectral flatness ({mean_flatness:.3f}) – synthetic/cloned voice indicator"
            )

        # ZCR std – AI voices have unnaturally consistent zero-crossings
        zcr = librosa.feature.zero_crossing_rate(y)[0]
        zcr_std = float(zcr.std())
        if zcr_std < 0.01:
            score += 20
            reasons.append("Unnaturally consistent zero-crossing rate – deepfake marker")

        # MFCC variance – AI voices lack natural speech texture
        mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
        mfcc_var = float(mfccs.var(axis=1).mean())
        if mfcc_var < 10:
            score += 20
            reasons.append(f"Low MFCC variance ({mfcc_var:.1f}) – lacks natural speech texture")

        # F0 jitter – natural voices wobble slightly every pitch cycle
        # Voice clones are unnaturally stable even when "distressed"
        f0, _, _ = librosa.pyin(
            y, fmin=librosa.note_to_hz('C2'), fmax=librosa.note_to_hz('C7')
        )
        f0_clean = f0[~np.isnan(f0)]
        if len(f0_clean) > 10:
            jitter = float(np.diff(f0_clean).std())
            if jitter < 2.0:
                score += 20
                reasons.append(
                    f"Very low F0 jitter ({jitter:.2f} Hz) – unnaturally stable pitch "
                    f"(human baseline: 4-8 Hz) — voice clone marker"
                )

        # Spectral envelope consistency — 3-second clones repeat spectral patterns
        # Compute variance of spectral centroids over time windows
        spec_centroid = librosa.feature.spectral_centroid(y=y, sr=sr)[0]
        centroid_std = float(spec_centroid.std())
        if centroid_std < 200 and len(spec_centroid) > 20:
            score += 15
            reasons.append(
                f"Unnaturally consistent spectral envelope (std: {centroid_std:.0f} Hz) – "
                f"voice cloning artifact"
            )

    except Exception as e:
        reasons.append(f"Deepfake detection error: {str(e)[:80]}")

    return min(score, 80.0), reasons


# ── Main Detector ───────────────────────────────────────────────────────────

class VoiceDetector:
    def __init__(self, vector_db: VectorDB = None):
        self.vector_db = vector_db

    def analyze(self, audio_bytes: bytes, filename: str) -> Dict[str, Any]:
        reasons = []

        # Layer 1 – Acoustics (includes boiler room + GSM preprocessing)
        a_score, a_reasons = acoustic_analysis(audio_bytes, filename)
        reasons.extend(a_reasons)

        # Layer 2 – Transcript → keyword + vector + PII scrub + Claude NLP
        transcript = transcribe(audio_bytes, filename)
        n_score, n_reasons = nlp_on_transcript(transcript, vector_db=self.vector_db)
        reasons.extend(n_reasons)

        # Layer 3 – Deepfake / voice clone detection
        d_score, d_reasons = deepfake_detection(audio_bytes, filename)
        reasons.extend(d_reasons)

        # Weighted combination
        final = (a_score * 0.25) + (n_score * 0.45) + (d_score * 0.30)

        # ── Deepfake Override Rule ───────────────────────────────────────────
        # If spectral analysis is highly confident this is AI-generated/cloned,
        # override the final score to HIGH RISK regardless of semantic layer.
        # A legitimate caller will NEVER use a cloned voice.
        is_deepfake = d_score > 40
        if d_score > 70:
            final = max(final, 85.0)
            reasons.insert(0,
                "OVERRIDE: High-confidence AI voice clone detected — "
                "automatic HIGH RISK (spectral physics confirm synthetic generation)"
            )

        return ThreatScore.build(
            score=final,
            reasons=reasons,
            source="voice",
            raw={
                "transcript": transcript[:500] if transcript else "",
                "acoustic_score": round(a_score, 1),
                "nlp_score": round(n_score, 1),
                "deepfake_score": round(d_score, 1),
                "is_deepfake": is_deepfake,
                "deepfake_override": d_score > 70,
            },
        )
