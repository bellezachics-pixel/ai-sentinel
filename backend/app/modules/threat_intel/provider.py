"""
AI-Sentinel Threat Intelligence Provider Module

Integrates with VirusTotal, Urlscan.io, and AbuseIPDB APIs.
Gracefully handles missing API keys and service unavailability.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any

import httpx

# Attempt to import config for API keys; gracefully degrade if unavailable
try:
    from app.core.config import settings

    VIRUSTOTAL_API_KEY: str | None = getattr(settings, "VIRUSTOTAL_API_KEY", None)
    URLSCAN_API_KEY: str | None = getattr(settings, "URLSCAN_API_KEY", None)
    ABUSEIPDB_API_KEY: str | None = getattr(settings, "ABUSEIPDB_API_KEY", None)
except (ImportError, AttributeError):
    VIRUSTOTAL_API_KEY = None
    URLSCAN_API_KEY = None
    ABUSEIPDB_API_KEY = None

# Indicator type constants
INDICATOR_URL = "url"
INDICATOR_IP = "ip"
INDICATOR_DOMAIN = "domain"
INDICATOR_HASH = "hash"

# API base URLs
VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


class ThreatIntelProvider:
    """Aggregates threat intelligence from multiple providers."""

    def __init__(
        self,
        virustotal_key: str | None = None,
        urlscan_key: str | None = None,
        abuseipdb_key: str | None = None,
    ) -> None:
        self.vt_key = virustotal_key or VIRUSTOTAL_API_KEY
        self.urlscan_key = urlscan_key or URLSCAN_API_KEY
        self.abuseipdb_key = abuseipdb_key or ABUSEIPDB_API_KEY

    @staticmethod
    def _detect_indicator_type(indicator: str) -> str:
        """Auto-detect the type of an indicator."""
        indicator = indicator.strip()

        # Hash detection (MD5, SHA1, SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$", indicator):
            return INDICATOR_HASH
        if re.match(r"^[a-fA-F0-9]{40}$", indicator):
            return INDICATOR_HASH
        if re.match(r"^[a-fA-F0-9]{64}$", indicator):
            return INDICATOR_HASH

        # IP detection
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
            return INDICATOR_IP

        # URL detection
        if indicator.startswith(("http://", "https://", "hxxp://", "hxxps://")):
            return INDICATOR_URL

        # Default to domain
        if "." in indicator and not indicator.startswith("/"):
            return INDICATOR_DOMAIN

        return INDICATOR_URL

    # ---- VirusTotal ----

    async def query_virustotal(
        self, indicator: str, indicator_type: str | None = None
    ) -> dict[str, Any]:
        """
        Query VirusTotal for an indicator.

        Supports URLs, IPs, domains, and file hashes.
        """
        result: dict[str, Any] = {
            "provider": "virustotal",
            "indicator": indicator,
            "available": False,
            "data": {},
            "error": None,
        }

        if not self.vt_key:
            result["error"] = "VirusTotal API key not configured"
            return result

        if indicator_type is None:
            indicator_type = self._detect_indicator_type(indicator)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {"x-apikey": self.vt_key}

                if indicator_type == INDICATOR_URL:
                    # URL must be base64url-encoded for VT API
                    import base64
                    url_id = base64.urlsafe_b64encode(
                        indicator.encode()
                    ).decode().rstrip("=")
                    endpoint = f"{VT_BASE}/urls/{url_id}"
                elif indicator_type == INDICATOR_IP:
                    endpoint = f"{VT_BASE}/ip_addresses/{indicator}"
                elif indicator_type == INDICATOR_DOMAIN:
                    endpoint = f"{VT_BASE}/domains/{indicator}"
                elif indicator_type == INDICATOR_HASH:
                    endpoint = f"{VT_BASE}/files/{indicator}"
                else:
                    result["error"] = f"Unsupported indicator type: {indicator_type}"
                    return result

                response = await client.get(endpoint, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    result["available"] = True
                    result["data"] = {
                        "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                        "reputation": attrs.get("reputation"),
                        "total_votes": attrs.get("total_votes", {}),
                        "last_analysis_date": attrs.get("last_analysis_date"),
                        "categories": attrs.get("categories", {}),
                    }

                    # Calculate detection ratio
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 0
                    result["data"]["detection_ratio"] = (
                        f"{malicious}/{total}" if total > 0 else "0/0"
                    )
                    result["data"]["is_malicious"] = malicious > 0

                elif response.status_code == 404:
                    result["available"] = True
                    result["data"] = {"found": False, "detail": "Not found in VirusTotal"}
                elif response.status_code == 429:
                    result["error"] = "VirusTotal API rate limit exceeded"
                elif response.status_code == 401:
                    result["error"] = "VirusTotal API key is invalid"
                else:
                    result["error"] = (
                        f"VirusTotal returned status {response.status_code}"
                    )

        except httpx.TimeoutException:
            result["error"] = "VirusTotal request timed out"
        except httpx.ConnectError:
            result["error"] = "Could not connect to VirusTotal"
        except Exception as exc:
            result["error"] = f"VirusTotal query failed: {str(exc)}"

        return result

    # ---- Urlscan.io ----

    async def query_urlscan(self, url: str) -> dict[str, Any]:
        """
        Submit a URL to urlscan.io and retrieve scan results.

        If the URL has been scanned before, returns cached results.
        Otherwise submits a new scan and returns the submission ID.
        """
        result: dict[str, Any] = {
            "provider": "urlscan",
            "indicator": url,
            "available": False,
            "data": {},
            "error": None,
        }

        if not self.urlscan_key:
            result["error"] = "Urlscan.io API key not configured"
            return result

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {"API-Key": self.urlscan_key}

                # First, search for existing scans
                search_url = f"{URLSCAN_BASE}/search/?q=page.url:\"{url}\"&size=1"
                search_resp = await client.get(search_url, headers=headers)

                if search_resp.status_code == 200:
                    search_data = search_resp.json()
                    results_list = search_data.get("results", [])

                    if results_list:
                        # Return most recent scan result
                        latest = results_list[0]
                        result["available"] = True
                        result["data"] = {
                            "scan_id": latest.get("_id"),
                            "scan_url": latest.get("result"),
                            "page": latest.get("page", {}),
                            "stats": latest.get("stats", {}),
                            "verdicts": latest.get("verdicts", {}),
                            "task": latest.get("task", {}),
                            "source": "cached",
                        }

                        # Fetch detailed results if available
                        result_url = latest.get("result")
                        if result_url:
                            try:
                                detail_resp = await client.get(result_url)
                                if detail_resp.status_code == 200:
                                    detail = detail_resp.json()
                                    verdicts = detail.get("verdicts", {})
                                    result["data"]["verdicts"] = verdicts
                                    result["data"]["lists"] = detail.get("lists", {})

                                    # Extract overall verdict
                                    overall = verdicts.get("overall", {})
                                    result["data"]["is_malicious"] = overall.get(
                                        "malicious", False
                                    )
                                    result["data"]["score"] = overall.get("score", 0)
                            except (httpx.TimeoutException, httpx.ConnectError):
                                pass  # Detail fetch is supplementary

                        return result

                # Submit new scan
                submit_data = {
                    "url": url,
                    "visibility": "unlisted",
                }
                submit_resp = await client.post(
                    f"{URLSCAN_BASE}/scan/",
                    json=submit_data,
                    headers={**headers, "Content-Type": "application/json"},
                )

                if submit_resp.status_code in (200, 201):
                    submit_result = submit_resp.json()
                    result["available"] = True
                    result["data"] = {
                        "scan_id": submit_result.get("uuid"),
                        "scan_url": submit_result.get("result"),
                        "api_url": submit_result.get("api"),
                        "visibility": submit_result.get("visibility"),
                        "source": "new_submission",
                        "message": "Scan submitted; results will be available shortly",
                    }
                elif submit_resp.status_code == 429:
                    result["error"] = "Urlscan.io API rate limit exceeded"
                elif submit_resp.status_code == 401:
                    result["error"] = "Urlscan.io API key is invalid"
                else:
                    result["error"] = (
                        f"Urlscan.io returned status {submit_resp.status_code}"
                    )

        except httpx.TimeoutException:
            result["error"] = "Urlscan.io request timed out"
        except httpx.ConnectError:
            result["error"] = "Could not connect to Urlscan.io"
        except Exception as exc:
            result["error"] = f"Urlscan.io query failed: {str(exc)}"

        return result

    # ---- AbuseIPDB ----

    async def query_abuseipdb(self, ip: str) -> dict[str, Any]:
        """
        Check an IP address reputation on AbuseIPDB.
        """
        result: dict[str, Any] = {
            "provider": "abuseipdb",
            "indicator": ip,
            "available": False,
            "data": {},
            "error": None,
        }

        if not self.abuseipdb_key:
            result["error"] = "AbuseIPDB API key not configured"
            return result

        # Validate IP format
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            result["error"] = f"Invalid IP address format: {ip}"
            return result

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {
                    "Key": self.abuseipdb_key,
                    "Accept": "application/json",
                }
                params = {
                    "ipAddress": ip,
                    "maxAgeInDays": "90",
                    "verbose": "",
                }

                response = await client.get(
                    f"{ABUSEIPDB_BASE}/check",
                    headers=headers,
                    params=params,
                )

                if response.status_code == 200:
                    data = response.json().get("data", {})
                    result["available"] = True
                    result["data"] = {
                        "ip_address": data.get("ipAddress"),
                        "is_public": data.get("isPublic"),
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "total_reports": data.get("totalReports", 0),
                        "num_distinct_users": data.get("numDistinctUsers", 0),
                        "last_reported_at": data.get("lastReportedAt"),
                        "usage_type": data.get("usageType"),
                        "is_tor": data.get("isTor", False),
                        "is_whitelisted": data.get("isWhitelisted"),
                    }

                    # Determine if malicious
                    confidence = data.get("abuseConfidenceScore", 0)
                    result["data"]["is_malicious"] = confidence > 50
                    result["data"]["risk_level"] = (
                        "critical" if confidence > 80
                        else "high" if confidence > 50
                        else "medium" if confidence > 25
                        else "low" if confidence > 0
                        else "safe"
                    )

                elif response.status_code == 429:
                    result["error"] = "AbuseIPDB API rate limit exceeded"
                elif response.status_code in (401, 403):
                    result["error"] = "AbuseIPDB API key is invalid or unauthorized"
                elif response.status_code == 422:
                    result["error"] = f"AbuseIPDB: Invalid IP address: {ip}"
                else:
                    result["error"] = (
                        f"AbuseIPDB returned status {response.status_code}"
                    )

        except httpx.TimeoutException:
            result["error"] = "AbuseIPDB request timed out"
        except httpx.ConnectError:
            result["error"] = "Could not connect to AbuseIPDB"
        except Exception as exc:
            result["error"] = f"AbuseIPDB query failed: {str(exc)}"

        return result

    # ---- Aggregated Query ----

    async def query_all(
        self, indicator: str, indicator_type: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Query all applicable threat intelligence providers for an indicator.

        Automatically determines which providers to query based on indicator type.

        Args:
            indicator: The IoC to look up (URL, IP, domain, or hash).
            indicator_type: Optional explicit type. Auto-detected if None.

        Returns:
            List of result dicts from each provider.
        """
        if indicator_type is None:
            indicator_type = self._detect_indicator_type(indicator)

        tasks: list[asyncio.Task[dict[str, Any]]] = []

        # VirusTotal supports all indicator types
        tasks.append(
            asyncio.create_task(
                self.query_virustotal(indicator, indicator_type)
            )
        )

        # Urlscan.io for URLs and domains
        if indicator_type in (INDICATOR_URL, INDICATOR_DOMAIN):
            url_to_scan = indicator
            if indicator_type == INDICATOR_DOMAIN:
                url_to_scan = f"https://{indicator}"
            tasks.append(
                asyncio.create_task(self.query_urlscan(url_to_scan))
            )

        # AbuseIPDB for IPs
        if indicator_type == INDICATOR_IP:
            tasks.append(
                asyncio.create_task(self.query_abuseipdb(indicator))
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, Exception):
                processed.append({
                    "provider": "unknown",
                    "indicator": indicator,
                    "available": False,
                    "data": {},
                    "error": f"Provider query raised exception: {str(r)}",
                })
            else:
                processed.append(r)

        return processed


# Module-level singleton
threat_intel_provider = ThreatIntelProvider()


async def query_all(
    indicator: str, indicator_type: str | None = None
) -> list[dict[str, Any]]:
    """Module-level convenience function."""
    return await threat_intel_provider.query_all(indicator, indicator_type)


async def query_virustotal(
    indicator: str, indicator_type: str | None = None
) -> dict[str, Any]:
    """Module-level convenience function."""
    return await threat_intel_provider.query_virustotal(indicator, indicator_type)


async def query_urlscan(url: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await threat_intel_provider.query_urlscan(url)


async def query_abuseipdb(ip: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await threat_intel_provider.query_abuseipdb(ip)
