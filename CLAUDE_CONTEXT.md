# Fraud Shield AI (Zora AI Evolution) - Development Context & Handoff
**Date:** April 1, 2026
**Team:** Phish Police
**Project Status:** Backend (100%), Frontend UI (Polished)

## 1. Core Mission & Blueprint
The project is "Fraud Shield AI," an evolved, superior version of the "Zora AI" concept. It is a multi-agent orchestration layer designed to stop state-of-the-art "Sovereign AI Agents" (deepfakes, bespoke spear-phishing traps). Legacy security relies on Known Bad Lists; this project uses a hierarchical defense pipeline to analyze inputs in real-time.

*   **Ingestion:** Plugins, UI Dashboard, IMAP scanning.
*   **Classifier:** Routes threats to specific scanners (Regex, NER, XGBoost, Llama 3, Whisper, Librosa, Yara).
*   **Security Gateway:** Shadow Guard (blocks prompt injection) and DLP Guard (prevents data leaks).
*   **Scoring:** A unified Threat Score (0-100) combining Text, URL, Voice, File, and Email assessments, refined by a precise Human-in-the-Loop feedback mechanism.

## 2. What We Have Completed Together Today
1.  **Read the Pitch Deck:** Extracted and fully analyzed `ppt_cad.pdf` using a custom PyMuPDF script. Mapped the 16-slide pitch perfectly against the codebase.
2.  **Backend Dependencies Setup:** Generated a comprehensive `backend/requirements.txt` encompassing all deep-tech libraries required (FastAPI, `xgboost`, `faster-whisper`, `librosa`, `yara-python`, `playwright`, `chromadb`, etc.).
3.  **Environment Variables Template:** Generated `backend/.env.example` mapping out Anthropic, IMAP, and VirusTotal keys.
<<<<<<< HEAD
4.  **Frontend "WOW" UI Overhaul:** Replaced the basic CSS with a highly premium, dark-mode "glassmorphism" aesthetic in `frontend/src/index.css`.
    *   Added glowing neon cyans (`#00f2fe`) and reds (`#ff2a5f`).
    *   Imported the modern 'Outfit' font.
    *   Added dynamic `backdrop-filter: blur(16px)` to component cards for a true Cybersecurity Command Center vibe.
=======
4.  **Frontend "WOW" UI Overhaul:** Replaced the basic CSS with a highly premium, dark-mode "glassmorphism" aesthetic in `frontend/src/index.css`. 
    *   Added glowing neon cyans (`#00f2fe`) and reds (`#ff2a5f`).
    *   Imported the modern 'Outfit' font.
    *   Added dynamic `backdrop-filter: blur(16px)` to component cards for a true Cybersecurity Command Center vibe. 
>>>>>>> 645ca9558ba883db1fbaa5ae3be7baf1723c142d
    *   Verified that React layout components (like `AnalyzeTab` and `FeedbackTab.jsx`) correctly inherit and deploy this styling.

## 3. The Live Voice Guard Pipeline (Deep Dive Explanations)
We structured the pitch explanations for the `backend/detectors/voice_detector.py` module. It is broken into three concurrent execution layers:

### Layer 1: Acoustic Feature Extraction (How it's said)
Uses `librosa` to analyze human emotional/physiological markers:
*   **Pitch Variance (`piptrack`):** Detects stress/agitation.
*   **Speaking Range (`beat_track`):** Flags rapid, scripted text-reading (> 150 BPM).
*   **RMS Energy Variance:** Detects pressure tactics & shouting.
*   **Silence Ratio:** Flags automated robocalls that never pause to breathe.

### Layer 2: Semantic Check / NLP (What is said)
*   **Speed:** Uses `faster-whisper` quantized to `int8` on the CPU for sub-200ms local transcription (bypassing slow API latency).
*   **Intent Detection:** Scans transcripts for Scam Vectors (e.g., "OTP", "Aadhaar", "AnyDesk") and triggers massive multipliers if coupled with Urgency Language (e.g., "immediately", "last chance").

### Layer 3: Deepfake Voice Detection (Is it human?)
Measures mathematical artifacts left behind by ElevenLabs or Sovereign AI generators:
*   **Spectral Flatness:** AI generates unnaturally "smooth" sound frequencies.
*   **Zero-Crossing Rate (ZCR):** Machine-learning models output sound blocks without natural human breath disruption.
*   **MFCC Variance:** AI struggles to map the high physical geometry variance of a human mouth changing shape.
*   **F0 Jitter:** Detects the absolute lack of tiny, involuntary vocal cord micro-fluctuations (< 2.0Hz jitter).

**Final Execution:** All three run instantaneously inside `VoiceDetector.analyze()` and are triangulated together (25% Acoustic + 45% NLP + 30% Deepfake) to return the final Threat Score. Future roadmap includes replacing deterministic thresholds with an XGBoost ML classifier.
