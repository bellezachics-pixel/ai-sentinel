"""
AI-Sentinel Content Analyzer Module

Analyzes HTML/text content for social engineering patterns, credential
harvesting forms, obfuscated JavaScript, suspicious iframes, and hidden
redirects.
"""

from __future__ import annotations

import re
from typing import Any


# --- Pattern Definitions ---

URGENCY_PATTERNS: list[tuple[str, str]] = [
    (r"\b(immediate(?:ly)?|urgent(?:ly)?|right\s+now|act\s+now)\b", "urgency_immediate"),
    (r"\b(expire[sd]?|expir(?:ing|ation)|deadline|limited\s+time)\b", "urgency_expiration"),
    (r"\b(suspend(?:ed)?|terminat(?:ed?|ion)|deactivat(?:ed?|ion)|locked|disabled)\b", "urgency_threat"),
    (r"\b(verify\s+(?:your|now)|confirm\s+(?:your|now)|validate\s+(?:your|now))\b", "urgency_verify"),
    (r"\b(within\s+\d+\s+(?:hour|minute|day)s?|last\s+chance|final\s+warning)\b", "urgency_countdown"),
    (r"\b(unauthorized\s+(?:access|activity|transaction))\b", "urgency_unauthorized"),
]

IMPERSONATION_PATTERNS: list[tuple[str, str]] = [
    (r"\b(security\s+(?:team|department|center|alert))\b", "impersonation_security_team"),
    (r"\b(customer\s+(?:support|service|care))\b", "impersonation_support"),
    (r"\b((?:it|tech(?:nical)?)\s+(?:support|department|team|helpdesk))\b", "impersonation_it"),
    (r"\b(paypal|microsoft|apple|google|amazon|netflix|bank)\b", "impersonation_brand"),
    (r"\b(dear\s+(?:customer|user|member|valued|account\s+holder))\b", "impersonation_greeting"),
    (r"\b(official\s+(?:notice|communication|notification))\b", "impersonation_official"),
]

CREDENTIAL_HARVEST_PATTERNS: list[tuple[str, str]] = [
    (r"<form[^>]*action\s*=\s*[\"'][^\"']*[\"']", "form_with_action"),
    (r"<input[^>]*type\s*=\s*[\"']password[\"']", "password_input"),
    (r"<input[^>]*(?:name|id)\s*=\s*[\"'](?:user|email|login|pass|pwd|ssn|credit|card)", "sensitive_input_field"),
    (r"<form[^>]*method\s*=\s*[\"']post[\"']", "post_form"),
]

OBFUSCATION_PATTERNS: list[tuple[str, str]] = [
    (r"eval\s*\(", "js_eval"),
    (r"document\.write\s*\(", "js_document_write"),
    (r"unescape\s*\(", "js_unescape"),
    (r"fromCharCode", "js_fromcharcode"),
    (r"atob\s*\(", "js_atob"),
    (r"\\x[0-9a-fA-F]{2}", "hex_encoding"),
    (r"\\u[0-9a-fA-F]{4}", "unicode_encoding"),
    (r"String\.fromCharCode\s*\([\d,\s]+\)", "js_string_construction"),
    (r"(?:window|document)\s*\[\s*[\"']", "bracket_notation_access"),
    (r"setTimeout\s*\(\s*[\"']", "settimeout_string"),
    (r"new\s+Function\s*\(", "function_constructor"),
]

IFRAME_PATTERNS: list[tuple[str, str]] = [
    (r"<iframe[^>]*(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0))", "hidden_iframe"),
    (r"<iframe[^>]*src\s*=\s*[\"'](?:data:|javascript:)", "data_uri_iframe"),
    (r"<iframe[^>]*src\s*=\s*[\"']https?://(?!(?:www\.)?(?:youtube|vimeo|google|microsoft))", "external_iframe"),
]

REDIRECT_PATTERNS: list[tuple[str, str]] = [
    (r"<meta[^>]*http-equiv\s*=\s*[\"']refresh[\"'][^>]*content\s*=\s*[\"']\d+\s*;\s*url\s*=", "meta_refresh_redirect"),
    (r"window\.location\s*(?:\.href\s*)?=", "js_location_redirect"),
    (r"location\.replace\s*\(", "js_location_replace"),
    (r"window\.open\s*\(", "js_window_open"),
    (r"document\.location\s*=", "js_document_location"),
    (r"top\.location\s*=", "js_top_location"),
]


class ContentAnalyzer:
    """Analyzes HTML/text content for social engineering and phishing indicators."""

    def _scan_patterns(
        self,
        content: str,
        patterns: list[tuple[str, str]],
        category: str,
        severity: str = "medium",
    ) -> list[dict[str, Any]]:
        """Scan content against a list of regex patterns."""
        findings: list[dict[str, Any]] = []
        seen_types: set[str] = set()

        for pattern, pattern_type in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                if pattern_type not in seen_types:
                    seen_types.add(pattern_type)
                    findings.append({
                        "category": category,
                        "pattern_type": pattern_type,
                        "severity": severity,
                        "matched_text": match.group(0)[:200],
                        "position": match.start(),
                    })
        return findings

    def _analyze_urgency(self, content: str) -> list[dict[str, Any]]:
        """Detect urgency and pressure language."""
        return self._scan_patterns(content, URGENCY_PATTERNS, "urgency_language", "medium")

    def _analyze_impersonation(self, content: str) -> list[dict[str, Any]]:
        """Detect impersonation attempts."""
        return self._scan_patterns(content, IMPERSONATION_PATTERNS, "impersonation", "high")

    def _analyze_credential_harvesting(self, content: str) -> list[dict[str, Any]]:
        """Detect credential harvesting forms."""
        findings = self._scan_patterns(
            content, CREDENTIAL_HARVEST_PATTERNS, "credential_harvesting", "high"
        )

        # Check for forms posting to external domains
        form_actions = re.finditer(
            r"<form[^>]*action\s*=\s*[\"'](https?://[^\"']+)[\"']",
            content,
            re.IGNORECASE,
        )
        for match in form_actions:
            findings.append({
                "category": "credential_harvesting",
                "pattern_type": "external_form_action",
                "severity": "critical",
                "matched_text": match.group(0)[:200],
                "action_url": match.group(1)[:500],
                "position": match.start(),
            })

        # Check for autocomplete off on password fields (anti-browser-save)
        if re.search(
            r"autocomplete\s*=\s*[\"']off[\"'][^>]*type\s*=\s*[\"']password[\"']",
            content,
            re.IGNORECASE,
        ):
            findings.append({
                "category": "credential_harvesting",
                "pattern_type": "autocomplete_disabled",
                "severity": "medium",
                "detail": "Password field has autocomplete disabled, common in phishing",
            })

        return findings

    def _analyze_obfuscation(self, content: str) -> list[dict[str, Any]]:
        """Detect obfuscated JavaScript."""
        findings = self._scan_patterns(
            content, OBFUSCATION_PATTERNS, "obfuscated_javascript", "high"
        )

        # Check for heavily encoded content
        encoded_ratio = content.count("\\x") + content.count("\\u") + content.count("%")
        if len(content) > 0 and (encoded_ratio / len(content)) > 0.1:
            findings.append({
                "category": "obfuscated_javascript",
                "pattern_type": "high_encoding_ratio",
                "severity": "high",
                "detail": f"Content has high encoding ratio ({encoded_ratio}/{len(content)})",
            })

        # Check for base64 encoded blocks
        b64_matches = re.findall(
            r"[A-Za-z0-9+/]{50,}={0,2}", content
        )
        if len(b64_matches) > 2:
            findings.append({
                "category": "obfuscated_javascript",
                "pattern_type": "base64_blocks",
                "severity": "medium",
                "detail": f"Found {len(b64_matches)} potential base64-encoded blocks",
            })

        return findings

    def _analyze_iframes(self, content: str) -> list[dict[str, Any]]:
        """Detect suspicious iframes."""
        return self._scan_patterns(content, IFRAME_PATTERNS, "suspicious_iframe", "high")

    def _analyze_redirects(self, content: str) -> list[dict[str, Any]]:
        """Detect hidden redirects."""
        return self._scan_patterns(content, REDIRECT_PATTERNS, "hidden_redirect", "high")

    def _analyze_text_content(self, content: str) -> list[dict[str, Any]]:
        """Analyze plain text content for social engineering."""
        findings: list[dict[str, Any]] = []
        findings.extend(self._analyze_urgency(content))
        findings.extend(self._analyze_impersonation(content))

        # Check for suspicious links in text
        urls = re.findall(r"https?://[^\s<>\"']+", content)
        if urls:
            findings.append({
                "category": "embedded_links",
                "pattern_type": "urls_in_text",
                "severity": "low",
                "detail": f"Found {len(urls)} embedded URL(s)",
                "urls": urls[:10],
            })

        return findings

    def _calculate_score(self, findings: list[dict[str, Any]]) -> int:
        """Calculate a 0-100 risk score based on findings."""
        if not findings:
            return 0

        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
        }

        score = 0
        category_counts: dict[str, int] = {}

        for finding in findings:
            severity = finding.get("severity", "low")
            category = finding.get("category", "unknown")
            category_counts[category] = category_counts.get(category, 0) + 1
            score += severity_weights.get(severity, 3)

        # Bonus for multiple categories being triggered (compound attack)
        if len(category_counts) >= 3:
            score += 15
        elif len(category_counts) >= 2:
            score += 8

        return min(score, 100)

    async def analyze_content(
        self,
        content: str,
        content_type: str = "html",
    ) -> dict[str, Any]:
        """
        Analyze HTML or text content for phishing and social engineering indicators.

        Args:
            content: The content string to analyze.
            content_type: Either "html" or "text".

        Returns:
            Dictionary with 'score', 'findings', and 'metadata' keys.
        """
        try:
            if not content or not isinstance(content, str):
                return {
                    "score": 0,
                    "findings": [],
                    "metadata": {"error": "Invalid or empty content provided"},
                }

            all_findings: list[dict[str, Any]] = []

            if content_type == "html":
                all_findings.extend(self._analyze_urgency(content))
                all_findings.extend(self._analyze_impersonation(content))
                all_findings.extend(self._analyze_credential_harvesting(content))
                all_findings.extend(self._analyze_obfuscation(content))
                all_findings.extend(self._analyze_iframes(content))
                all_findings.extend(self._analyze_redirects(content))
            else:
                all_findings.extend(self._analyze_text_content(content))

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

            # Summarize categories
            categories_found = list({f["category"] for f in all_findings})

            return {
                "score": score,
                "risk_level": risk_level,
                "findings": all_findings,
                "metadata": {
                    "content_type": content_type,
                    "content_length": len(content),
                    "categories_detected": categories_found,
                    "total_findings": len(all_findings),
                    "analysis_type": "content_analysis",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"Content analysis failed: {str(exc)}",
                    "content_type": content_type,
                    "analysis_type": "content_analysis",
                },
            }


# Module-level singleton
content_analyzer = ContentAnalyzer()


async def analyze_content(
    content: str, content_type: str = "html"
) -> dict[str, Any]:
    """Module-level convenience function."""
    return await content_analyzer.analyze_content(content, content_type)
