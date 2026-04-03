"""URLScan.io integration for behavioral URL analysis"""
import logging
import time
import asyncio

import httpx

from models import URLScanFinding
from typing import Optional

logger = logging.getLogger(__name__)


class URLScanScanner:
    """Queries URLScan.io for behavioral analysis and screenshots"""

    BASE_URL = "https://urlscan.io/api/v1"

    # URLScan needs time to render pages; we give it a generous window.
    SUBMIT_TIMEOUT = 15          # seconds for the POST /scan call
    POLL_TIMEOUT = 45            # total seconds to poll for result
    POLL_INITIAL_DELAY = 5       # first poll after this many seconds
    POLL_INTERVAL = 3            # seconds between subsequent polls
    MAX_POLL_INTERVAL = 8        # back-off cap

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"API-Key": api_key, "Content-Type": "application/json"}

    async def scan(self, url: str, timeout: int | None = None) -> Optional[URLScanFinding]:
        """
        Submit URL to URLScan.io and retrieve behavioral analysis.

        1. Submits the URL for scanning
        2. Waits for scan completion (polling with back-off)
        3. Returns findings with screenshot URL

        Returns:
            URLScanFinding or None if scan fails / times out
        """
        poll_timeout = timeout or self.POLL_TIMEOUT
        try:
            async with httpx.AsyncClient(timeout=self.SUBMIT_TIMEOUT) as client:
                # --- Submit scan ---
                submit_response = await client.post(
                    f"{self.BASE_URL}/scan/",
                    headers=self.headers,
                    json={"url": url, "visibility": "public"},
                )
                submit_response.raise_for_status()
                scan_data = submit_response.json()
                scan_uuid = scan_data.get("uuid")

                if not scan_uuid:
                    logger.warning("URLScan: No UUID returned")
                    return None

                logger.info("URLScan submitted: %s", scan_uuid)

            # Use a separate client with a longer timeout for polling
            async with httpx.AsyncClient(timeout=poll_timeout) as poll_client:
                result = await self._poll_results(poll_client, scan_uuid, poll_timeout)
                return result

        except httpx.HTTPError as e:
            logger.warning("URLScan API error for %s: %s", url, e)
            return None
        except Exception as e:
            logger.error("URLScan scan error: %s", e)
            return None

    async def _poll_results(
        self,
        client: httpx.AsyncClient,
        scan_uuid: str,
        timeout: int,
    ) -> Optional[URLScanFinding]:
        """Poll URLScan.io for scan results with exponential back-off."""
        start = time.monotonic()
        interval = self.POLL_INTERVAL

        # Give the scan a head-start before first poll
        await asyncio.sleep(self.POLL_INITIAL_DELAY)

        while time.monotonic() - start < timeout:
            try:
                response = await client.get(
                    f"{self.BASE_URL}/result/{scan_uuid}/",
                    headers=self.headers,
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_response(data, scan_uuid)
                elif response.status_code == 404:
                    logger.debug("Scan %s not ready yet, retrying in %ds...", scan_uuid, interval)
                else:
                    logger.warning("URLScan unexpected status %d for %s", response.status_code, scan_uuid)

            except Exception as e:
                logger.warning("Error polling URLScan results: %s", e)

            await asyncio.sleep(interval)
            interval = min(self.MAX_POLL_INTERVAL, interval + 1)

        logger.warning("URLScan poll timeout after %ds for %s", timeout, scan_uuid)
        # Return a partial finding so the UUID is at least visible in the response
        return URLScanFinding(scan_uuid=scan_uuid, page_title="[scan timed out]")

    def _parse_response(self, data: dict, scan_uuid: str = "") -> URLScanFinding:
        """Parse URLScan.io API response into an URLScanFinding."""
        try:
            page = data.get("page", {})
            stats = data.get("stats", {})
            screenshot = data.get("screenshot")

            # Redirect chain
            redirect_chain: list[str] = []
            for req in data.get("requests", []):
                status = req.get("response", {}).get("status")
                if status in (301, 302, 303, 307, 308):
                    redir_url = req.get("request", {}).get("url", "")
                    if redir_url:
                        redirect_chain.append(redir_url)

            # Ads/trackers
            ads = data.get("lists", {}).get("ads", [])

            return URLScanFinding(
                scan_uuid=scan_uuid or data.get("_id"),
                screenshot_url=screenshot,
                dom_text_length=stats.get("domainsLength", 0),
                page_title=page.get("title"),
                http_status_code=page.get("status"),
                page_domain=page.get("domain"),
                final_url=page.get("url"),
                redirect_chain=redirect_chain,
                ads=ads if isinstance(ads, list) else [],
                matches=data.get("verdicts", {}),
            )
        except Exception as e:
            logger.error("Error parsing URLScan response: %s", e)
            return URLScanFinding(scan_uuid=scan_uuid)
