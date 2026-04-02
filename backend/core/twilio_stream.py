"""
Twilio Media Streams Handler
─────────────────────────────
Twilio sends audio as base64-encoded mulaw (G.711) chunks via WebSocket.
This module:
  1. Receives Twilio stream events
  2. Decodes mulaw → PCM → WAV
  3. Accumulates 5s worth of audio
  4. Feeds into process_chunk() → RiskState
  5. Pushes score updates to the frontend via a separate WebSocket

Twilio stream message format:
  {"event": "media", "media": {"payload": "<base64 mulaw>"}}
  {"event": "start", "start": {"callSid": "...", "streamSid": "..."}}
  {"event": "stop"}
"""

import base64
import audioop
import io
import json
import struct
import wave
from typing import Dict

from core.live_call import process_chunk, end_call, get_or_create_call

# Twilio sends mulaw 8kHz mono
TWILIO_SAMPLE_RATE = 8000
TWILIO_CHANNELS = 1
CHUNK_DURATION_SEC = 5
SAMPLES_PER_CHUNK = TWILIO_SAMPLE_RATE * CHUNK_DURATION_SEC  # 40000 samples


def mulaw_to_wav(mulaw_bytes: bytes) -> bytes:
    """Convert raw mulaw bytes to WAV format (PCM 16-bit 8kHz mono)."""
    # mulaw → linear PCM
    pcm_bytes = audioop.ulaw2lin(mulaw_bytes, 2)  # 2 = 16-bit

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(TWILIO_CHANNELS)
        wf.setsampwidth(2)  # 16-bit
        wf.setframerate(TWILIO_SAMPLE_RATE)
        wf.writeframes(pcm_bytes)
    return buf.getvalue()


class TwilioStreamHandler:
    """
    One instance per active Twilio call.
    Accumulates mulaw chunks, fires analysis every 5 seconds.
    """

    def __init__(self, call_sid: str, vector_db=None, frontend_ws=None):
        self.call_sid = call_sid
        self.vector_db = vector_db
        self.frontend_ws = frontend_ws  # WebSocket to push scores to browser
        self._mulaw_buffer: bytes = b""
        self._chunk_count = 0

    async def handle_message(self, raw: str) -> dict | None:
        """
        Process one Twilio WebSocket message.
        Returns analysis result dict if a chunk was processed, else None.
        """
        try:
            msg = json.loads(raw)
        except Exception:
            return None

        event = msg.get("event")

        if event == "start":
            call_sid = msg.get("start", {}).get("callSid", self.call_sid)
            self.call_sid = call_sid
            get_or_create_call(call_sid)
            return {"event": "started", "call_sid": call_sid}

        elif event == "media":
            payload = msg.get("media", {}).get("payload", "")
            if not payload:
                return None

            mulaw_chunk = base64.b64decode(payload)
            self._mulaw_buffer += mulaw_chunk

            # Fire analysis every 5 seconds worth of audio
            bytes_per_sample = 1  # mulaw = 1 byte per sample
            chunk_bytes = SAMPLES_PER_CHUNK * bytes_per_sample

            if len(self._mulaw_buffer) >= chunk_bytes:
                chunk = self._mulaw_buffer[:chunk_bytes]
                self._mulaw_buffer = self._mulaw_buffer[chunk_bytes:]
                self._chunk_count += 1

                wav_bytes = mulaw_to_wav(chunk)
                result = process_chunk(self.call_sid, wav_bytes, self.vector_db)
                result["type"] = "chunk_result"
                result["chunk_number"] = self._chunk_count

                # Push to frontend browser WebSocket if connected
                if self.frontend_ws:
                    try:
                        await self.frontend_ws.send_text(json.dumps(result))
                        if result.get("alert"):
                            await self.frontend_ws.send_text(json.dumps({
                                "type": "alert",
                                "call_id": self.call_sid,
                                "score": result["current_score"],
                                "message": "HIGH RISK SCAM DETECTED — Hang up immediately!",
                                "intent_progression": result.get("intent_progression", []),
                            }))
                    except Exception:
                        pass

                return result

        elif event == "stop":
            state = end_call(self.call_sid)
            if self.frontend_ws and state:
                try:
                    await self.frontend_ws.send_text(json.dumps({
                        "type": "call_ended",
                        "final_score": round(state.current_score, 1),
                        "verdict": state.to_dict()["verdict"],
                        "full_transcript": state.transcript_so_far,
                        "intent_progression": state.intent_progression,
                    }))
                except Exception:
                    pass
            return {"event": "stopped", "call_sid": self.call_sid}

        return None


# ── Active handlers store ────────────────────────────────────────────────────
_handlers: Dict[str, TwilioStreamHandler] = {}


def get_or_create_handler(call_sid: str, vector_db=None, frontend_ws=None) -> TwilioStreamHandler:
    if call_sid not in _handlers:
        _handlers[call_sid] = TwilioStreamHandler(call_sid, vector_db, frontend_ws)
    return _handlers[call_sid]


def remove_handler(call_sid: str):
    _handlers.pop(call_sid, None)
