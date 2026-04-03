"""Playwright-based browser automation for URL detonation"""
import logging
import time
from urllib.parse import urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

from models import PlaywrightFinding
from typing import Optional

logger = logging.getLogger(__name__)


class PlaywrightScanner:
    """Local headless browser for detecting phishing patterns and suspicious behavior"""

    # Patterns indicative of phishing / credential harvesting
    PHISHING_KEYWORDS = [
        "password", "login", "signin", "sign in", "authenticate",
        "confirm identity", "verify account", "update payment",
        "verify card", "billing address", "social security",
        "ssn", "OTP", "2FA", "verify phone",
    ]

    SUSPICIOUS_SCRIPT_KEYWORDS = [
        "eval", "document.write", "window.location", "ajax",
        "XMLHttpRequest", "fetch", "keylogger", "steal",
    ]

    def __init__(self):
        self.playwright = None
        self.browser = None

    async def scan(self, url: str, timeout: int = 15) -> Optional[PlaywrightFinding]:
        """
        Visit URL with headless browser and detect phishing indicators.

        Looks for:
        - Login/password forms
        - Redirects and navigation chains
        - Suspicious external requests
        - Malicious scripts

        Returns:
            PlaywrightFinding or None if scan fails
        """
        playwright = None
        browser = None
        context = None
        page = None

        try:
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Intercept requests for analysis
            requests_made: list[dict] = []

            def handle_request(request):
                requests_made.append({
                    "url": request.url,
                    "resource_type": request.resource_type,
                    "method": request.method,
                })

            page.on("request", handle_request)

            # Navigate with timeout — measure wallclock for response_time_ms
            nav_start = time.perf_counter()
            response = await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
            nav_elapsed_ms = int((time.perf_counter() - nav_start) * 1000)

            # Try the Playwright timing API; fall back to our own wallclock
            try:
                timing_val = response.timing["responseEnd"] if response else -1
                response_time_ms = int(timing_val) if timing_val and timing_val > 0 else nav_elapsed_ms
            except Exception:
                response_time_ms = nav_elapsed_ms

            finding = PlaywrightFinding(
                final_url=page.url,
                response_time_ms=response_time_ms,
            )

            # --- Form analysis ---
            forms = await page.query_selector_all("form")
            login_form_count = 0
            password_field_count = 0

            for form in forms:
                form_html = await form.evaluate("el => el.outerHTML")
                form_lower = form_html.lower()
                if any(kw in form_lower for kw in self.PHISHING_KEYWORDS):
                    login_form_count += 1
                password_fields = await form.query_selector_all("input[type='password']")
                password_field_count += len(password_fields)

            # Also count standalone password inputs outside forms
            all_pw_inputs = await page.query_selector_all("input[type='password']")
            password_field_count = max(password_field_count, len(all_pw_inputs))

            finding.login_forms_detected = login_form_count > 0
            finding.password_fields = password_field_count

            # --- Script analysis ---
            scripts = await page.query_selector_all("script")
            suspicious_scripts: list[str] = []

            for script in scripts:
                script_content = await script.evaluate("el => el.textContent")
                if script_content:
                    script_lower = script_content.lower()
                    for kw in self.SUSPICIOUS_SCRIPT_KEYWORDS:
                        if kw in script_lower:
                            suspicious_scripts.append(f"Contains '{kw}'")
                            break  # one match per script tag is enough

            finding.suspicious_scripts = suspicious_scripts

            # --- External requests ---
            page_domain = urlparse(url).netloc
            external_domains: set[str] = set()
            for req in requests_made:
                req_domain = urlparse(req["url"]).netloc
                if req_domain and req_domain != page_domain and req["resource_type"] in ("xhr", "fetch"):
                    external_domains.add(req_domain)

            finding.external_requests = [
                {"domain": d, "type": "external"} for d in list(external_domains)[:5]
            ]

            # --- Page text preview ---
            page_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
            finding.page_text_preview = (page_text[:200] if page_text else "")

            logger.info("Playwright scan complete for %s  (response %d ms)", url, response_time_ms)
            return finding

        except PlaywrightTimeoutError:
            logger.warning("Playwright timeout for %s", url)
            return PlaywrightFinding(
                final_url=url,
                errors=["Browser timeout — possibly intentional evasion"],
            )
        except Exception as e:
            logger.error("Playwright scan error: %s", e)
            return PlaywrightFinding(
                final_url=url,
                errors=[str(e)],
            )
        finally:
            if page:
                await page.close()
            if context:
                await context.close()
            if browser:
                await browser.close()
            if playwright:
                await playwright.stop()
