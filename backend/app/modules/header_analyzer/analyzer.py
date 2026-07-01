"""
AI-Sentinel HTTP Header Analyzer Module

Checks security headers, analyzes TLS certificate information, and detects
Adversary-in-the-Middle (AiTM) proxy indicators.
"""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx


# --- Security Header Definitions ---

REQUIRED_SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "high",
        "detail": "HTTP Strict Transport Security not set; vulnerable to downgrade attacks",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "high",
        "detail": "Content Security Policy not set; vulnerable to XSS and injection attacks",
        "recommended": "default-src 'self'; script-src 'self'",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "detail": "X-Frame-Options not set; vulnerable to clickjacking",
        "recommended": "DENY",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "detail": "X-Content-Type-Options not set; vulnerable to MIME sniffing",
        "recommended": "nosniff",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "detail": "X-XSS-Protection not set (legacy but still useful for older browsers)",
        "recommended": "1; mode=block",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "detail": "Referrer-Policy not set; may leak sensitive URL information",
        "recommended": "strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "detail": "Permissions-Policy not set; browser features not restricted",
        "recommended": "geolocation=(), camera=(), microphone=()",
    },
}

SUSPICIOUS_SERVER_HEADERS: set[str] = {
    "evilginx", "modlishka", "muraena", "gophish", "king-phisher",
    "nginx/0.", "apache/1.", "openresty",
}

AITM_PROXY_INDICATORS: list[str] = [
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "via",
    "x-real-ip",
    "cf-connecting-ip",
    "x-original-url",
    "x-rewrite-url",
]


class HeaderAnalyzer:
    """Analyzes HTTP headers and TLS certificates for security issues."""

    async def _fetch_headers(self, url: str) -> tuple[dict[str, str], int, str]:
        """Fetch HTTP headers from a URL."""
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            verify=True,
        ) as client:
            response = await client.head(url)
            headers = dict(response.headers)
            return headers, response.status_code, str(response.url)

    def _check_security_headers(
        self, headers: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Check for missing or misconfigured security headers."""
        findings: list[dict[str, Any]] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_key, info in REQUIRED_SECURITY_HEADERS.items():
            if header_key not in headers_lower:
                findings.append({
                    "category": "missing_security_header",
                    "header": info["name"],
                    "severity": info["severity"],
                    "detail": info["detail"],
                    "recommended_value": info["recommended"],
                })
            else:
                value = headers_lower[header_key]
                # Check for weak HSTS
                if header_key == "strict-transport-security":
                    if "max-age=0" in value:
                        findings.append({
                            "category": "weak_security_header",
                            "header": "HSTS",
                            "severity": "high",
                            "detail": "HSTS max-age is 0, effectively disabling it",
                            "current_value": value,
                        })
                    elif "includesubdomains" not in value.lower():
                        findings.append({
                            "category": "weak_security_header",
                            "header": "HSTS",
                            "severity": "low",
                            "detail": "HSTS does not include subdomains",
                            "current_value": value,
                        })

                # Check for weak CSP
                if header_key == "content-security-policy":
                    if "unsafe-inline" in value or "unsafe-eval" in value:
                        findings.append({
                            "category": "weak_security_header",
                            "header": "CSP",
                            "severity": "medium",
                            "detail": "CSP allows unsafe-inline or unsafe-eval",
                            "current_value": value[:500],
                        })
                    if "*" in value.split():
                        findings.append({
                            "category": "weak_security_header",
                            "header": "CSP",
                            "severity": "high",
                            "detail": "CSP uses wildcard (*) source, effectively disabling protection",
                            "current_value": value[:500],
                        })

        return findings

    def _detect_aitm_indicators(
        self, headers: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Detect Adversary-in-the-Middle proxy indicators in headers."""
        findings: list[dict[str, Any]] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check for proxy-related headers
        for proxy_header in AITM_PROXY_INDICATORS:
            if proxy_header in headers_lower:
                findings.append({
                    "category": "aitm_indicator",
                    "pattern_type": "proxy_header_present",
                    "header": proxy_header,
                    "severity": "medium",
                    "detail": f"Proxy-related header '{proxy_header}' detected",
                    "value": headers_lower[proxy_header][:200],
                })

        # Check for suspicious server headers
        server = headers_lower.get("server", "").lower()
        for suspicious in SUSPICIOUS_SERVER_HEADERS:
            if suspicious in server:
                findings.append({
                    "category": "aitm_indicator",
                    "pattern_type": "suspicious_server",
                    "severity": "critical",
                    "detail": f"Server header matches known phishing tool: {suspicious}",
                    "value": server,
                })

        # Check for unusual header combinations
        has_security_headers = sum(
            1 for h in REQUIRED_SECURITY_HEADERS if h in headers_lower
        )
        total_required = len(REQUIRED_SECURITY_HEADERS)
        if has_security_headers < total_required // 2:
            findings.append({
                "category": "aitm_indicator",
                "pattern_type": "missing_security_headers_bulk",
                "severity": "medium",
                "detail": (
                    f"Only {has_security_headers}/{total_required} security headers present; "
                    "proxies often strip security headers"
                ),
            })

        # Check for Set-Cookie without Secure/HttpOnly
        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie:
            if "secure" not in set_cookie.lower():
                findings.append({
                    "category": "aitm_indicator",
                    "pattern_type": "insecure_cookie",
                    "severity": "high",
                    "detail": "Cookie set without Secure flag; vulnerable to interception",
                })
            if "httponly" not in set_cookie.lower():
                findings.append({
                    "category": "aitm_indicator",
                    "pattern_type": "cookie_no_httponly",
                    "severity": "medium",
                    "detail": "Cookie set without HttpOnly flag; vulnerable to XSS theft",
                })

        return findings

    def _get_tls_info(self, hostname: str, port: int = 443) -> dict[str, Any]:
        """Retrieve TLS certificate information for a host."""
        tls_info: dict[str, Any] = {}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        tls_info["subject"] = dict(
                            x[0] for x in cert.get("subject", ())
                        )
                        tls_info["issuer"] = dict(
                            x[0] for x in cert.get("issuer", ())
                        )
                        tls_info["version"] = cert.get("version")
                        tls_info["serial_number"] = cert.get("serialNumber")
                        tls_info["not_before"] = cert.get("notBefore")
                        tls_info["not_after"] = cert.get("notAfter")
                        tls_info["protocol"] = ssock.version()

                        # Subject Alternative Names
                        san = cert.get("subjectAltName", ())
                        tls_info["san"] = [entry[1] for entry in san]

                        # Check certificate validity
                        not_after_str = cert.get("notAfter", "")
                        if not_after_str:
                            try:
                                not_after = datetime.strptime(
                                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                                )
                                not_after = not_after.replace(tzinfo=timezone.utc)
                                days_remaining = (
                                    not_after - datetime.now(timezone.utc)
                                ).days
                                tls_info["days_until_expiry"] = days_remaining
                                tls_info["is_expired"] = days_remaining < 0
                            except ValueError:
                                tls_info["days_until_expiry"] = None
                                tls_info["is_expired"] = None

        except ssl.SSLCertVerificationError as exc:
            tls_info["error"] = f"Certificate verification failed: {str(exc)}"
            tls_info["verification_failed"] = True
        except (socket.timeout, socket.gaierror, OSError) as exc:
            tls_info["error"] = f"Connection failed: {str(exc)}"

        return tls_info

    def _analyze_tls(
        self, tls_info: dict[str, Any], hostname: str
    ) -> list[dict[str, Any]]:
        """Analyze TLS certificate for security issues."""
        findings: list[dict[str, Any]] = []

        if tls_info.get("verification_failed"):
            findings.append({
                "category": "tls_issue",
                "pattern_type": "cert_verification_failed",
                "severity": "critical",
                "detail": tls_info.get("error", "Certificate verification failed"),
            })
            return findings

        if tls_info.get("error"):
            findings.append({
                "category": "tls_issue",
                "pattern_type": "connection_error",
                "severity": "high",
                "detail": tls_info["error"],
            })
            return findings

        # Check expiry
        if tls_info.get("is_expired"):
            findings.append({
                "category": "tls_issue",
                "pattern_type": "cert_expired",
                "severity": "critical",
                "detail": "TLS certificate has expired",
            })
        elif tls_info.get("days_until_expiry") is not None:
            days = tls_info["days_until_expiry"]
            if days < 7:
                findings.append({
                    "category": "tls_issue",
                    "pattern_type": "cert_expiring_soon",
                    "severity": "high",
                    "detail": f"TLS certificate expires in {days} day(s)",
                })
            elif days < 30:
                findings.append({
                    "category": "tls_issue",
                    "pattern_type": "cert_expiring_soon",
                    "severity": "medium",
                    "detail": f"TLS certificate expires in {days} day(s)",
                })

        # Check if hostname matches certificate
        san_list = tls_info.get("san", [])
        subject_cn = tls_info.get("subject", {}).get("commonName", "")
        all_names = set(san_list) | {subject_cn}

        hostname_matches = False
        for name in all_names:
            if name == hostname:
                hostname_matches = True
                break
            if name.startswith("*.") and hostname.endswith(name[1:]):
                hostname_matches = True
                break

        if not hostname_matches and all_names:
            findings.append({
                "category": "tls_issue",
                "pattern_type": "hostname_mismatch",
                "severity": "critical",
                "detail": f"Certificate does not match hostname '{hostname}'",
                "certificate_names": list(all_names)[:10],
            })

        # Check for free/automated CAs commonly used in phishing
        issuer_org = tls_info.get("issuer", {}).get("organizationName", "")
        issuer_cn = tls_info.get("issuer", {}).get("commonName", "")
        free_cas = ["let's encrypt", "zerossl", "buypass"]
        for ca in free_cas:
            if ca in issuer_org.lower() or ca in issuer_cn.lower():
                findings.append({
                    "category": "tls_info",
                    "pattern_type": "free_ca",
                    "severity": "low",
                    "detail": f"Certificate issued by free CA: {issuer_org or issuer_cn}",
                })
                break

        # Check for self-signed certificates
        subject = tls_info.get("subject", {})
        issuer = tls_info.get("issuer", {})
        if subject == issuer and subject:
            findings.append({
                "category": "tls_issue",
                "pattern_type": "self_signed",
                "severity": "high",
                "detail": "Certificate appears to be self-signed",
            })

        return findings

    def _calculate_score(self, findings: list[dict[str, Any]]) -> int:
        """Calculate a 0-100 risk score."""
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
        }
        score = sum(
            severity_weights.get(f.get("severity", "low"), 3)
            for f in findings
        )
        return min(score, 100)

    async def analyze_headers(self, url: str) -> dict[str, Any]:
        """
        Analyze HTTP headers and TLS certificate for a URL.

        Args:
            url: The URL to analyze.

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
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            all_findings: list[dict[str, Any]] = []
            headers_data: dict[str, str] = {}
            tls_info: dict[str, Any] = {}
            final_url = url
            status_code = 0

            # Fetch headers
            try:
                headers_data, status_code, final_url = await self._fetch_headers(url)
                security_findings = self._check_security_headers(headers_data)
                all_findings.extend(security_findings)

                aitm_findings = self._detect_aitm_indicators(headers_data)
                all_findings.extend(aitm_findings)
            except httpx.ConnectError:
                all_findings.append({
                    "category": "connection_error",
                    "severity": "high",
                    "detail": "Could not connect to the target URL",
                })
            except httpx.TimeoutException:
                all_findings.append({
                    "category": "connection_error",
                    "severity": "medium",
                    "detail": "Connection timed out while fetching headers",
                })
            except Exception as exc:
                all_findings.append({
                    "category": "connection_error",
                    "severity": "medium",
                    "detail": f"Error fetching headers: {str(exc)}",
                })

            # TLS analysis (only for HTTPS)
            if parsed.scheme == "https" and hostname:
                try:
                    tls_info = self._get_tls_info(hostname, port)
                    tls_findings = self._analyze_tls(tls_info, hostname)
                    all_findings.extend(tls_findings)
                except Exception as exc:
                    all_findings.append({
                        "category": "tls_issue",
                        "severity": "medium",
                        "detail": f"TLS analysis failed: {str(exc)}",
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
                    "url": url,
                    "final_url": final_url,
                    "status_code": status_code,
                    "hostname": hostname,
                    "headers": headers_data,
                    "tls_info": tls_info,
                    "analysis_type": "header_analysis",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"Header analysis failed: {str(exc)}",
                    "url": url,
                    "analysis_type": "header_analysis",
                },
            }


# Module-level singleton
header_analyzer = HeaderAnalyzer()


async def analyze_headers(url: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await header_analyzer.analyze_headers(url)
