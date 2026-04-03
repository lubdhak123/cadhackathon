# ============================================================
# Fraud Shield AI — URL Sandbox  (Dockerfile)
# ============================================================
# Build:   docker compose build
# Run:     docker compose up
# Test:    curl -X POST http://localhost:8000/scan-url \
#            -H "Content-Type: application/json" \
#            -d '{"url":"https://testsafebrowsing.appspot.com/s/phishing.html"}'
# ============================================================

FROM python:3.11-slim

# Prevent Python from writing .pyc / buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# ----- System deps for Playwright Chromium -----
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget gnupg ca-certificates fonts-liberation \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 libcups2 \
    libdbus-1-3 libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 \
    libx11-xcb1 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libxshmfence1 xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# ----- Python deps -----
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ----- Install Playwright browsers -----
RUN playwright install chromium && playwright install-deps chromium

# ----- App code -----
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
