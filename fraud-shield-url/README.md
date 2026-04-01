# URL Sandbox – Fraud Shield AI

Real-time behavioral URL analysis and threat scoring system. Detects phishing, malicious redirects, and credential harvesting attacks by combining three parallel analysis methods.

## 🎯 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. Configure API Keys
Copy `.env.example` to `.env` and add your API keys:
```bash
cp .env.example .env
```

Fill in:
- `VIRUSTOTAL_API_KEY`: Get from https://virustotal.com/gui/my-apikey
- `URLSCAN_API_KEY`: Get from https://urlscan.io/api/

### 3. Run Server
```bash
python app.py
```
Server starts at `http://localhost:8000`

### 4. Test the Endpoint
```bash
curl -X POST http://localhost:8000/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## 📋 Architecture

The URL Sandbox runs three parallel checks:

### 1. **VirusTotal** (Known-Bad Database)
- Instant lookup against 90+ antivirus engines
- Returns detection count and categories
- Fast, but only catches already-known threats

### 2. **URLScan.io** (Cloud Behavioral Sandbox)
- Full page rendering + screenshot
- Tracks redirect chains
- Identifies ads, trackers, and suspicious patterns
- Good at catching redirection chains and domain mismatches

### 3. **Playwright** (Local Browser Analysis)
- Live headless Chrome execution
- Detects login forms and password fields
- Monitors JavaScript execution and external requests
- Catches runtime phishing behaviors

### Scoring Logic
- **VirusTotal**: 35% weight (known threats)
- **URLScan.io**: 35% weight (behavioral redirects)
- **Playwright**: 30% weight (runtime detection)

Outputs: **Threat Score** (0–100) + **Reason** (human-readable)

## 📁 Project Structure
```
fraud-shield-url/
├── app.py                    # FastAPI main application
├── config.py                 # Environment config & settings
├── models.py                 # Pydantic data models
├── scoring.py                # Risk scoring logic
├── scanners/
│   ├── __init__.py
│   ├── virustotal.py         # VirusTotal API integration
│   ├── urlscan.py            # URLScan.io API integration
│   └── playwright_scanner.py # Browser automation
├── requirements.txt          # Dependencies
├── .env.example              # API key template
└── README.md                 # This file
```

## 🔌 API Reference

### POST /scan-url
Scan a URL for threats.

**Request:**
```json
{
  "url": "https://suspicious-link.com",
  "force_rescan": false,
  "timeout_override": null
}
```

**Response:**
```json
{
  "scan_id": "uuid-here",
  "url": "https://suspicious-link.com",
  "threat_score": 87,
  "reason": "Credential form detected (phishing indicator) | redirects to credential-harvesting page",
  "findings": {
    "virustotal": {
      "detection_count": 5,
      "undetected_count": 45,
      "suspicious_count": 2,
      "latest_scan_date": "2025-01-15",
      "categories": {},
      "scan_id": "abc123"
    },
    "urlscan": {
      "scan_uuid": "uuid",
      "screenshot_url": "https://...",
      "redirect_chain": ["https://...", "https://..."],
      "http_status_code": 200,
      "final_url": "https://..."
    },
    "playwright": {
      "login_forms_detected": true,
      "password_fields": 2,
      "suspicious_scripts": ["Suspicious script #1"],
      "external_requests": [{"domain": "tracker.com", "type": "external"}],
      "redirect_count": 1
    }
  },
  "timestamp": "2025-01-15T10:30:45.123456"
}
```

### GET /health
Health check endpoint.

### GET /
Service information.

## 🧪 Testing

Run the test suite:
```bash
pytest tests/ -v
```

## 🚀 Deployment

For production, consider:
1. Running multiple Playwright instances in an async pool
2. Caching VirusTotal/URLScan results
3. Rate-limiting API calls to external services
4. Adding request signing for the Risk Scoring Engine

## 📝 Notes

- **Playwright startup**: First launch of Chromium takes ~5-10s. Subsequent requests are faster.
- **API Rate Limits**: VirusTotal (4 req/min free tier), URLScan.io (check your plan)
- **Timeouts**: Configure in `.env` for different network conditions
- **Docker**: For MVP purposes, this runs locally. Production deployment can use Docker later.

## 🔒 Security

- API keys stored in `.env` (not committed to Git)
- Playwright runs in headless mode only (no visual attack surface)
- External requests monitored but not executed
- All user input validated via Pydantic

## 🤝 Integration with Risk Scoring Engine

This component outputs structured JSON that feeds directly into the central Risk Scoring Engine:

```python
{
  "component": "url_sandbox",
  "findings": {...},  # Raw findings from all three scanners
  "threat_score": 87, # 0-100
  "reason": "..."     # Human-readable explanation
}
```

The central engine combines this with signals from voice deepfake detection, email headers, SMS analysis, etc.

---

**Built for Fraud Shield AI – CAD 4.0 Cybersecurity**
