"""
AI-Sentinel QRishing Analyzer Module

Decodes QR codes from images, extracts and analyzes embedded URLs,
detects URL shorteners and suspicious redirects within QR payloads.
"""

from __future__ import annotations

import io
import re
from typing import Any
from urllib.parse import urlparse

KNOWN_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "v.gd", "qr.ae", "t.ly", "surl.li", "short.io",
}

SUSPICIOUS_SCHEMES: set[str] = {
    "javascript", "data", "vbscript", "blob",
}

SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
    ".club", ".work", ".date", ".racing", ".win", ".bid", ".stream",
    ".download", ".loan", ".men", ".click", ".link", ".site",
    ".online", ".icu", ".rest", ".fit",
}


class QRishingAnalyzer:
    """Analyzes QR codes for phishing (QRishing) indicators."""

    def _decode_qr(self, image_data: bytes) -> list[dict[str, Any]]:
        """
        Decode QR codes from image data.

        Uses pyzbar if available, falls back to a stub that reports
        the library is unavailable.
        """
        decoded_items: list[dict[str, Any]] = []

        try:
            from PIL import Image
            from pyzbar.pyzbar import decode as pyzbar_decode

            image = Image.open(io.BytesIO(image_data))
            results = pyzbar_decode(image)

            for result in results:
                data = result.data.decode("utf-8", errors="replace")
                decoded_items.append({
                    "data": data,
                    "type": result.type,
                    "rect": {
                        "left": result.rect.left,
                        "top": result.rect.top,
                        "width": result.rect.width,
                        "height": result.rect.height,
                    },
                    "quality": getattr(result, "quality", None),
                })

        except ImportError:
            # pyzbar or PIL not installed; try PIL-only approach
            try:
                from PIL import Image

                image = Image.open(io.BytesIO(image_data))
                decoded_items.append({
                    "data": None,
                    "type": "UNAVAILABLE",
                    "error": (
                        "pyzbar library not installed. "
                        "Install with: pip install pyzbar"
                    ),
                    "image_size": image.size,
                    "image_format": image.format,
                })
            except ImportError:
                decoded_items.append({
                    "data": None,
                    "type": "UNAVAILABLE",
                    "error": (
                        "PIL and pyzbar libraries not installed. "
                        "Install with: pip install Pillow pyzbar"
                    ),
                })
        except Exception as exc:
            decoded_items.append({
                "data": None,
                "type": "ERROR",
                "error": f"QR decode failed: {str(exc)}",
            })

        return decoded_items

    def _extract_urls(self, data: str) -> list[str]:
        """Extract URLs from decoded QR data."""
        urls: list[str] = []
        # Match explicit URLs
        url_pattern = re.compile(
            r"https?://[^\s<>\"']+|"
            r"(?:www\.)[^\s<>\"']+\.[a-zA-Z]{2,}[^\s<>\"']*"
        )
        for match in url_pattern.finditer(data):
            url = match.group(0)
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            urls.append(url)

        # If the entire data looks like a URL
        if not urls and re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", data):
            urls.append(data)

        return urls

    def _analyze_url(self, url: str) -> list[dict[str, Any]]:
        """Analyze a single URL extracted from a QR code."""
        findings: list[dict[str, Any]] = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme or ""

        # Suspicious scheme
        if scheme.lower() in SUSPICIOUS_SCHEMES:
            findings.append({
                "category": "qrishing",
                "pattern_type": "suspicious_scheme",
                "severity": "critical",
                "detail": f"QR code contains '{scheme}:' URI, likely malicious",
                "url": url[:500],
            })

        # URL shortener
        if hostname.lower() in KNOWN_SHORTENERS:
            findings.append({
                "category": "qrishing",
                "pattern_type": "url_shortener",
                "severity": "medium",
                "detail": f"QR code uses URL shortener '{hostname}', hiding true destination",
                "url": url[:500],
            })

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                findings.append({
                    "category": "qrishing",
                    "pattern_type": "suspicious_tld",
                    "severity": "medium",
                    "detail": f"URL uses suspicious TLD '{tld}'",
                    "url": url[:500],
                })
                break

        # IP address as hostname
        try:
            import socket as _socket
            _socket.inet_aton(hostname)
            findings.append({
                "category": "qrishing",
                "pattern_type": "ip_address_url",
                "severity": "high",
                "detail": "QR code URL uses an IP address instead of a domain name",
                "url": url[:500],
            })
        except (OSError, ValueError):
            pass

        # No HTTPS
        if scheme == "http":
            findings.append({
                "category": "qrishing",
                "pattern_type": "no_https",
                "severity": "medium",
                "detail": "QR code URL does not use HTTPS",
                "url": url[:500],
            })

        # Excessive URL length
        if len(url) > 200:
            findings.append({
                "category": "qrishing",
                "pattern_type": "excessive_length",
                "severity": "low",
                "detail": f"QR code URL is unusually long ({len(url)} chars)",
                "url": url[:500],
            })

        # Redirect parameters
        redirect_params = [
            "redirect", "url", "next", "return", "goto", "dest",
            "destination", "rurl", "returnurl", "continue",
        ]
        query_lower = (parsed.query or "").lower()
        for rp in redirect_params:
            if f"{rp}=" in query_lower:
                findings.append({
                    "category": "qrishing",
                    "pattern_type": "redirect_parameter",
                    "severity": "medium",
                    "detail": f"URL contains redirect parameter '{rp}'",
                    "url": url[:500],
                })
                break

        # Brand impersonation in hostname
        brands = [
            "paypal", "microsoft", "apple", "google", "amazon",
            "netflix", "facebook", "instagram", "bank", "chase",
        ]
        for brand in brands:
            if brand in hostname.lower() and not hostname.endswith(f".{brand}.com"):
                findings.append({
                    "category": "qrishing",
                    "pattern_type": "brand_impersonation",
                    "severity": "high",
                    "detail": f"Brand '{brand}' in hostname but not on official domain",
                    "url": url[:500],
                })
                break

        return findings

    def _analyze_non_url_data(self, data: str) -> list[dict[str, Any]]:
        """Analyze non-URL QR code data for suspicious content."""
        findings: list[dict[str, Any]] = []

        # Check for WiFi network configs (potential evil twin)
        if data.startswith("WIFI:"):
            findings.append({
                "category": "qrishing",
                "pattern_type": "wifi_config",
                "severity": "medium",
                "detail": "QR code contains WiFi configuration; verify network authenticity",
                "data": data[:200],
            })

        # Check for vCard/contact data with URLs
        if data.startswith("BEGIN:VCARD"):
            urls_in_vcard = re.findall(r"URL[;:](.+)", data)
            if urls_in_vcard:
                findings.append({
                    "category": "qrishing",
                    "pattern_type": "vcard_with_urls",
                    "severity": "low",
                    "detail": "QR code contains vCard with embedded URLs",
                    "urls": urls_in_vcard[:5],
                })

        # Check for SMS/tel schemes
        if data.startswith(("sms:", "tel:", "smsto:", "mmsto:")):
            findings.append({
                "category": "qrishing",
                "pattern_type": "communication_scheme",
                "severity": "low",
                "detail": f"QR code triggers communication: {data[:50]}",
            })

        # Check for email schemes
        if data.startswith("mailto:"):
            findings.append({
                "category": "qrishing",
                "pattern_type": "email_scheme",
                "severity": "low",
                "detail": "QR code triggers email composition",
                "data": data[:200],
            })

        return findings

    def _calculate_score(self, findings: list[dict[str, Any]]) -> int:
        """Calculate a 0-100 risk score."""
        severity_weights = {
            "critical": 30,
            "high": 20,
            "medium": 10,
            "low": 3,
        }
        score = sum(
            severity_weights.get(f.get("severity", "low"), 3)
            for f in findings
        )
        return min(score, 100)

    async def analyze_qr(self, image_data: bytes) -> dict[str, Any]:
        """
        Analyze a QR code image for QRishing indicators.

        Args:
            image_data: Raw image bytes containing a QR code.

        Returns:
            Dictionary with 'score', 'findings', and 'metadata' keys.
        """
        try:
            if not image_data:
                return {
                    "score": 0,
                    "findings": [],
                    "metadata": {"error": "No image data provided"},
                }

            # Decode QR codes
            decoded_items = self._decode_qr(image_data)

            all_findings: list[dict[str, Any]] = []
            extracted_urls: list[str] = []
            decoded_data: list[str] = []

            for item in decoded_items:
                if item.get("error"):
                    all_findings.append({
                        "category": "qr_decode",
                        "pattern_type": "decode_issue",
                        "severity": "low",
                        "detail": item["error"],
                    })
                    continue

                data = item.get("data")
                if not data:
                    continue

                decoded_data.append(data)

                # Extract and analyze URLs
                urls = self._extract_urls(data)
                extracted_urls.extend(urls)

                for url in urls:
                    url_findings = self._analyze_url(url)
                    all_findings.extend(url_findings)

                # Analyze non-URL data
                if not urls:
                    non_url_findings = self._analyze_non_url_data(data)
                    all_findings.extend(non_url_findings)

            # Multiple QR codes in one image is suspicious
            if len(decoded_items) > 1 and all(
                item.get("data") for item in decoded_items
            ):
                all_findings.append({
                    "category": "qrishing",
                    "pattern_type": "multiple_qr_codes",
                    "severity": "medium",
                    "detail": f"Image contains {len(decoded_items)} QR codes",
                })

            score = self._calculate_score(all_findings)

            risk_level = "safe"
            if score >= 75:
                risk_level = "critical"
            elif score >= 50:
                risk_level = "high"
            elif score >= 25:
                risk_level = "medium"
            elif score > 0:
                risk_level = "low"

            return {
                "score": score,
                "risk_level": risk_level,
                "findings": all_findings,
                "metadata": {
                    "qr_codes_found": len(decoded_items),
                    "decoded_data": decoded_data,
                    "extracted_urls": extracted_urls,
                    "image_size_bytes": len(image_data),
                    "analysis_type": "qrishing_analysis",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"QR analysis failed: {str(exc)}",
                    "analysis_type": "qrishing_analysis",
                },
            }


# Module-level singleton
qrishing_analyzer = QRishingAnalyzer()


async def analyze_qr(image_data: bytes) -> dict[str, Any]:
    """Module-level convenience function."""
    return await qrishing_analyzer.analyze_qr(image_data)
