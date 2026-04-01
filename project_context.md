# Fraud Shield AI – URL Sandbox Component

## 📋 Project Overview
**Fraud Shield AI**: Real-time, multi-channel AI defense system that intercepts scams at attack moment (email, SMS, voice, link, attachment) with a single 0–100 Threat Score.

**Problem**: Legacy tools (Truecaller, Gmail, antivirus) rely on "known bad" blocklists. Modern scammers use sovereign AI agents generating brand-new personalized attacks every time:
- 54% click rate on phishing
- Voice clones sound 95% human
- Links detect sandboxes and behave normally until reaching real humans
- India projected to lose ₹70,000 crore in 2025 to deepfake fraud alone

**Your Component**: URL Sandbox (Behavioral URL Analysis / Safe Browser Sandboxing)

---

## 🎯 URL Sandbox MVP Specification

### What It Must Do
1. **Accept URLs** via FastAPI endpoint (`POST /scan-url`)
2. **Run three parallel checks**:
   - **VirusTotal**: Check known-bad database (instant)
   - **URLScan.io**: Cloud sandbox behavioral report + screenshot
   - **Playwright**: Local headless Chrome following redirects, detecting password fields, fake login pages, suspicious external calls
3. **Combine results** into structured JSON with risk sub-score (0–100) + plain-English reason
4. **Return to Risk Scoring Engine** in clean format

### Example Output
```json
{
  "threat_score": 97,
  "reason": "Redirects to credential-harvesting page impersonating HDFC Bank, password fields detected, contacting suspicious tracker",
  "findings": {
    "url_redirects": [...],
    "login_forms_detected": true,
    "virustotal_detections": 15,
    "urlscan_screenshot": "...",
    "playwright_alerts": [...]
  }
}
```

### Tech Stack (MVP Only)
- **Framework**: FastAPI
- **Local Browser**: Playwright (headless Chrome)
- **External APIs**: VirusTotal API + URLScan.io API
- **NO DOCKER in MVP** – add Docker wording to pitch deck; judges care about demo working, not container architecture

---

## ⚠️ Scope Reality Check
**DO NOT attempt**:
- Full Docker container orchestration with network isolation
- Prompt injection guards (Shadow Guard – teammate responsibility)
- IMAP live email hooking (teammate responsibility)
- XGBoost classifier (teammate responsibility)
- Voice deepfake detection (teammate responsibility)
- DLP Guard (teammate responsibility)

**ONLY build** the URL Sandbox component. Everything else is a separate subsystem.

---

## ✅ Deliverables Checklist
- [ ] FastAPI project scaffolding with dependency management
- [ ] VirusTotal API integration (keys + async calling)
- [ ] URLScan.io API integration (async + screenshot handling)
- [ ] Playwright browser automation (headless Chrome, redirect following, form detection)
- [ ] Risk scoring logic combining all three sources
- [ ] JSON response formatting for Risk Scoring Engine
- [ ] Input validation & error handling
- [ ] Basic logging & debugging
- [ ] Demo-ready endpoint (/scan-url with sample calls)

---

## 🚀 Implementation Strategy
**Timeline-conscious approach** (you mentioned low personal time + 24-hour hackathon):

1. **Day 1 – Setup & Module Skeleton**
   - FastAPI project with async/await throughout
   - Dependency injection for API clients (VirusTotal, URLScan)
   - Basic error handling & validation

2. **Day 1/2 – API Integrations**
   - VirusTotal: Async HTTP calls, parse detections
   - URLScan.io: Submit scan, poll results, download screenshot
   - Playwright: Async Chrome launch, URL visit, form detection

3. **Day 2 – Risk Scoring & Testing**
   - Combine three signals into 0–100 score
   - Generate human-readable explanations
   - Test with known phishing URLs + legitimate sites
   - Format JSON for downstream Risk Scoring Engine

4. **Demo Day – Integration**
   - Verify endpoint works with teammate's Risk Scoring Engine
   - Show live URL scan → screenshot + score + reasoning
   - Have fallback data for API rate limits

---

## Last Task
- Initialized Git repository in project directory
- Configured GitHub remote: `https://github.com/lubdhak123/cadhackathon`
- Verified remote configuration with `git remote -v`

## Files Modified (This Session)
- None (Git setup only)

Previous session files:
- ✅ project_context.md – Full specification & scope boundaries
- ✅ fraud-shield-url/requirements.txt – All dependencies
- ✅ fraud-shield-url/.env.example – API key template
- ✅ fraud-shield-url/config.py – Settings management
- ✅ fraud-shield-url/models.py – Pydantic data models
- ✅ fraud-shield-url/app.py – FastAPI main application
- ✅ fraud-shield-url/scoring.py – Risk scoring logic
- ✅ fraud-shield-url/scanners/virustotal.py – VirusTotal API
- ✅ fraud-shield-url/scanners/urlscan.py – URLScan.io API
- ✅ fraud-shield-url/scanners/playwright_scanner.py – Browser automation
- ✅ fraud-shield-url/README.md – Complete documentation
- ✅ fraud-shield-url/tests/ – Test suite (test_app.py, test_scoring.py)
- ✅ fraud-shield-url/.gitignore – Git ignore rules

## Next Steps (Priority Order)
1. **Git Setup** (5 min)
   - [ ] `git add .` to stage all files
   - [ ] `git commit -m "Initial commit: URL Sandbox MVP"`
   - [ ] `git push -u origin main` (or `master` depending on default branch)

2. **Dependency Installation** (5 min)
   - [ ] Run `pip install -r requirements.txt`
   - [ ] Run `playwright install chromium`

3. **Local Testing** (15 min)
   - [ ] Start server: `python app.py`
   - [ ] Test health endpoint: `curl http://localhost:8000/health`
   - [ ] Test scan endpoint with known phishing URL

4. **Refinement & Demo Prep** (20 min)
   - [ ] Verify JSON output matches Risk Scoring Engine format
   - [ ] Test with 5+ known phishing URLs (document threat scores)
   - [ ] Test with 5+ legitimate sites (verify low scores)
   - [ ] Add error handling for API rate limits

5. **Integration with Team** (Day of Demo)
   - [ ] Share endpoint URL format with Risk Scoring Engine developer
   - [ ] Verify JSON field names match expected schema
   - [ ] Have fallback/mock data for demo if APIs hit rate limits
   - [ ] Practice running demo: URL → screenshot + score + reasoning
