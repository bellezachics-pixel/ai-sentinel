"""
AI-Sentinel URL Analyzer Module

Extracts URL features, checks for phishing patterns, homograph attacks,
and calculates a 0-100 risk score for any given URL.
"""

from __future__ import annotations

import re
import socket
import unicodedata
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
    ".club", ".work", ".date", ".racing", ".win", ".bid", ".stream",
    ".download", ".loan", ".men", ".click", ".link", ".info", ".site",
    ".online", ".icu", ".rest", ".fit",
}

KNOWN_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
    "rb.gy", "v.gd", "qr.ae",
}

BRAND_KEYWORDS: set[str] = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "chase", "wellsfargo", "bankofamerica", "citibank", "usps",
    "fedex", "dhl", "irs", "dropbox", "icloud", "outlook",
    "office365", "onedrive", "sharepoint",
}

HOMOGRAPH_CONFUSABLES: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0455": "s", "\u0458": "j", "\u04bb": "h", "\u0501": "d",
    "\u0261": "g", "\u026a": "i", "\u1d00": "a",
}


class URLAnalyzer:
    """Stateless URL risk analyzer."""

    def _extract_features(self, url: str) -> dict[str, Any]:
        """Extract structural features from a URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        full = unquote(url)

        features: dict[str, Any] = {
            "length": len(url),
            "hostname": hostname,
            "scheme": parsed.scheme,
            "path_depth": len([s for s in path.split("/") if s]),
            "has_ip": self._has_ip_address(hostname),
            "special_char_count": sum(
                1 for c in full if c in "@!#$%^&*()=+[]{}|;:',<>?"
            ),
            "subdomain_count": max(len(hostname.split(".")) - 2, 0),
            "has_at_symbol": "@" in url,
            "has_double_slash_redirect": "//" in path,
            "uses_https": parsed.scheme == "https",
            "query_param_count": len(parse_qs(query)),
            "has_suspicious_tld": any(
                hostname.endswith(tld) for tld in SUSPICIOUS_TLDS
            ),
            "is_shortener": hostname in KNOWN_SHORTENERS,
            "has_punycode": hostname.startswith("xn--") or ".xn--" in hostname,
            "entropy": self._shannon_entropy(hostname),
        }
        return features

    @staticmethod
    def _has_ip_address(hostname: str) -> bool:
        """Check if the hostname is an IP address."""
        try:
            socket.inet_aton(hostname)
            return True
        except (socket.error, OSError):
            pass
        # Check for hex/octal obfuscated IPs
        if re.match(r"^0x[0-9a-fA-F]+$", hostname):
            return True
        if re.match(r"^\d{8,}$", hostname):
            return True
        return False

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        import math
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _detect_homograph(self, hostname: str) -> list[dict[str, str]]:
        """Detect homograph / IDN spoofing attacks."""
        findings: list[dict[str, str]] = []
        for i, char in enumerate(hostname):
            if char in HOMOGRAPH_CONFUSABLES:
                findings.append({
                    "position": str(i),
                    "char": char,
                    "looks_like": HOMOGRAPH_CONFUSABLES[char],
                    "unicode_name": unicodedata.name(char, "UNKNOWN"),
                })
        if findings:
            # Check if mixed scripts are present
            scripts: set[str] = set()
            for char in hostname:
                if char.isalpha():
                    try:
                        scripts.add(unicodedata.name(char, "").split()[0])
                    except (ValueError, IndexError):
                        pass
            if len(scripts) > 1:
                findings.append({
                    "type": "mixed_script",
                    "scripts": ", ".join(sorted(scripts)),
                    "detail": "Hostname uses characters from multiple Unicode scripts",
                })
        return findings

    def _check_phishing_patterns(self, url: str) -> list[dict[str, Any]]:
        """Check for known phishing URL patterns."""
        findings: list[dict[str, Any]] = []
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = (parsed.path or "").lower()
        full_lower = url.lower()

        # Brand impersonation in subdomain or path
        for brand in BRAND_KEYWORDS:
            if brand in hostname and not hostname.endswith(f".{brand}.com"):
                findings.append({
                    "pattern": "brand_impersonation",
                    "brand": brand,
                    "severity": "high",
                    "detail": f"Brand '{brand}' found in hostname but not on official domain",
                })

        # Login/credential harvesting paths
        credential_paths = [
            "login", "signin", "sign-in", "log-in", "auth", "authenticate",
            "verify", "verification", "confirm", "secure", "account",
            "update", "password", "credential", "webmail",
        ]
        for cp in credential_paths:
            if cp in path:
                findings.append({
                    "pattern": "credential_harvesting_path",
                    "keyword": cp,
                    "severity": "medium",
                    "detail": f"Credential-related keyword '{cp}' in URL path",
                })
                break

        # Data URI scheme
        if full_lower.startswith("data:"):
            findings.append({
                "pattern": "data_uri",
                "severity": "high",
                "detail": "Data URI scheme used - can embed phishing content inline",
            })

        # Redirect patterns
        redirect_params = ["redirect", "url", "next", "return", "goto", "dest",
                           "destination", "rurl", "returnurl", "continue"]
        query_lower = (parsed.query or "").lower()
        for rp in redirect_params:
            if f"{rp}=" in query_lower:
                findings.append({
                    "pattern": "open_redirect",
                    "parameter": rp,
                    "severity": "medium",
                    "detail": f"Potential open redirect via '{rp}' parameter",
                })

        # Excessive subdomains (typosquatting / confusion)
        subdomain_count = max(len(hostname.split(".")) - 2, 0)
        if subdomain_count >= 3:
            findings.append({
                "pattern": "excessive_subdomains",
                "count": subdomain_count,
                "severity": "medium",
                "detail": f"URL has {subdomain_count} subdomains, possibly to confuse users",
            })

        # URL contains encoded characters that could hide intent
        if "%00" in url or "%0a" in url.lower() or "%0d" in url.lower():
            findings.append({
                "pattern": "null_byte_injection",
                "severity": "high",
                "detail": "URL contains null bytes or CRLF injection characters",
            })

        return findings

    def _calculate_score(
        self,
        features: dict[str, Any],
        phishing_findings: list[dict[str, Any]],
        homograph_findings: list[dict[str, str]],
    ) -> int:
        """Calculate a 0-100 risk score (higher = more dangerous)."""
        score = 0

        # Feature-based scoring
        if features["has_ip"]:
            score += 25
        if not features["uses_https"]:
            score += 10
        if features["has_suspicious_tld"]:
            score += 15
        if features["is_shortener"]:
            score += 10
        if features["has_punycode"]:
            score += 15
        if features["has_at_symbol"]:
            score += 15
        if features["has_double_slash_redirect"]:
            score += 10
        if features["length"] > 100:
            score += 5
        if features["length"] > 200:
            score += 5
        if features["subdomain_count"] >= 3:
            score += 10
        if features["special_char_count"] > 5:
            score += 5
        if features["entropy"] > 4.0:
            score += 5

        # Phishing pattern scoring
        severity_scores = {"high": 20, "medium": 10, "low": 5}
        for finding in phishing_findings:
            score += severity_scores.get(finding.get("severity", "low"), 5)

        # Homograph scoring
        if homograph_findings:
            score += min(len(homograph_findings) * 10, 30)

        return min(score, 100)

    async def analyze_url(self, url: str) -> dict[str, Any]:
        """
        Analyze a URL for phishing and malicious indicators.

        Args:
            url: The URL string to analyze.

        Returns:
            Dictionary with 'score', 'findings', and 'metadata' keys.
        """
        try:
            if not url or not isinstance(url, str):
                return {
                    "score": 0,
                    "findings": [],
                    "metadata": {"error": "Invalid or empty URL provided"},
                }

            url = url.strip()

            # Add scheme if missing for parsing
            parse_url = url
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_url):
                parse_url = f"https://{parse_url}"

            features = self._extract_features(parse_url)
            phishing_findings = self._check_phishing_patterns(parse_url)
            homograph_findings = self._detect_homograph(features["hostname"])

            score = self._calculate_score(features, phishing_findings, homograph_findings)

            # Compile all findings
            all_findings: list[dict[str, Any]] = []
            for pf in phishing_findings:
                all_findings.append({
                    "category": "phishing_pattern",
                    **pf,
                })
            for hf in homograph_findings:
                all_findings.append({
                    "category": "homograph_attack",
                    "severity": "high",
                    **hf,
                })

            # Add feature-based findings
            if features["has_ip"]:
                all_findings.append({
                    "category": "suspicious_feature",
                    "pattern": "ip_address_hostname",
                    "severity": "high",
                    "detail": "URL uses an IP address instead of a domain name",
                })
            if not features["uses_https"]:
                all_findings.append({
                    "category": "suspicious_feature",
                    "pattern": "no_https",
                    "severity": "medium",
                    "detail": "URL does not use HTTPS encryption",
                })
            if features["has_suspicious_tld"]:
                all_findings.append({
                    "category": "suspicious_feature",
                    "pattern": "suspicious_tld",
                    "severity": "medium",
                    "detail": "URL uses a TLD commonly associated with abuse",
                })
            if features["is_shortener"]:
                all_findings.append({
                    "category": "suspicious_feature",
                    "pattern": "url_shortener",
                    "severity": "low",
                    "detail": "URL uses a shortening service, hiding the true destination",
                })

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
                    "url": url,
                    "features": features,
                    "analysis_type": "url_analysis",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"URL analysis failed: {str(exc)}",
                    "url": url,
                    "analysis_type": "url_analysis",
                },
            }


# Module-level singleton for convenience
url_analyzer = URLAnalyzer()


async def analyze_url(url: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await url_analyzer.analyze_url(url)
