"""
AI-Sentinel OCR & NLP Analyzer Module

Provides image text extraction (OCR placeholder using PIL) and NLP-based
analysis for spear phishing detection and social engineering pattern
recognition.
"""

from __future__ import annotations

import io
import re
from typing import Any


# --- Social Engineering Pattern Definitions ---

URGENCY_PHRASES: list[tuple[str, float]] = [
    (r"\b(act\s+now|immediate(?:ly)?|urgent(?:ly)?|right\s+away)\b", 0.8),
    (r"\b(expire[sd]?|expir(?:ing|ation)|deadline|limited\s+time)\b", 0.7),
    (r"\b(last\s+chance|final\s+(?:warning|notice)|time\s+sensitive)\b", 0.8),
    (r"\b(within\s+\d+\s+(?:hour|minute|day)s?)\b", 0.7),
    (r"\b(don'?t\s+delay|respond\s+(?:immediately|now|asap))\b", 0.7),
    (r"\b(failure\s+to\s+(?:respond|comply|act))\b", 0.8),
]

AUTHORITY_PHRASES: list[tuple[str, float]] = [
    (r"\b(security\s+(?:team|department|center|division|office))\b", 0.7),
    (r"\b((?:it|tech(?:nical)?)\s+(?:support|department|team|admin))\b", 0.7),
    (r"\b(human\s+resources|hr\s+department|compliance\s+(?:team|office))\b", 0.6),
    (r"\b((?:chief|senior|head)\s+(?:executive|officer|director|manager))\b", 0.6),
    (r"\b(legal\s+(?:department|team|counsel|notice))\b", 0.7),
    (r"\b(official\s+(?:notice|communication|notification|memo))\b", 0.6),
    (r"\b(board\s+of\s+directors|executive\s+(?:team|office))\b", 0.5),
]

THREAT_PHRASES: list[tuple[str, float]] = [
    (r"\b(account\s+(?:suspend|terminat|deactivat|lock|clos|restrict)(?:ed|ion)?)\b", 0.8),
    (r"\b(unauthorized\s+(?:access|activity|transaction|login))\b", 0.9),
    (r"\b(security\s+(?:breach|incident|alert|violation))\b", 0.8),
    (r"\b(suspicious\s+(?:activity|login|transaction|behavior))\b", 0.7),
    (r"\b(legal\s+(?:action|consequences|proceedings))\b", 0.7),
    (r"\b(penalty|fine|prosecution|lawsuit)\b", 0.6),
    (r"\b(data\s+(?:breach|leak|exposure|compromise))\b", 0.8),
]

CREDENTIAL_REQUEST_PHRASES: list[tuple[str, float]] = [
    (r"\b(verify\s+your\s+(?:identity|account|credentials|information))\b", 0.9),
    (r"\b(confirm\s+your\s+(?:password|login|account|details))\b", 0.9),
    (r"\b(update\s+your\s+(?:password|credentials|payment|billing))\b", 0.8),
    (r"\b(enter\s+your\s+(?:password|username|email|ssn|credit\s+card))\b", 0.9),
    (r"\b(click\s+(?:here|below|the\s+link)\s+to\s+(?:verify|confirm|update|login))\b", 0.8),
    (r"\b(reset\s+your\s+password)\b", 0.5),
    (r"\b(provide\s+(?:your|the\s+following)\s+(?:information|details|credentials))\b", 0.8),
]

REWARD_PHRASES: list[tuple[str, float]] = [
    (r"\b(you(?:'ve)?\s+(?:won|been\s+selected|been\s+chosen))\b", 0.8),
    (r"\b(congratulations|winner|prize|reward|gift\s+card)\b", 0.7),
    (r"\b(claim\s+your\s+(?:prize|reward|gift|bonus))\b", 0.8),
    (r"\b(free\s+(?:gift|trial|offer|bonus|money))\b", 0.6),
    (r"\b(exclusive\s+(?:offer|deal|opportunity|invitation))\b", 0.5),
]

IMPERSONATION_PHRASES: list[tuple[str, float]] = [
    (r"\b(dear\s+(?:customer|user|member|valued|sir|madam|employee))\b", 0.5),
    (r"\b(on\s+behalf\s+of)\b", 0.4),
    (r"\b(this\s+is\s+(?:a\s+)?(?:notice|notification|reminder)\s+from)\b", 0.6),
    (r"\b((?:paypal|microsoft|apple|google|amazon|netflix|bank)\s+(?:team|support|security))\b", 0.8),
]

# Spear phishing indicators (personalization)
SPEAR_PHISHING_INDICATORS: list[tuple[str, float]] = [
    (r"\b(as\s+(?:discussed|mentioned|per\s+our\s+conversation))\b", 0.6),
    (r"\b(following\s+up\s+on)\b", 0.4),
    (r"\b(attached\s+(?:is|are|please\s+find))\b", 0.3),
    (r"\b(per\s+your\s+request)\b", 0.5),
    (r"\b(as\s+we\s+(?:discussed|agreed|spoke\s+about))\b", 0.5),
    (r"\b(your\s+(?:recent|latest)\s+(?:order|purchase|transaction))\b", 0.6),
]


class OCRNLPAnalyzer:
    """OCR text extraction and NLP-based social engineering detection."""

    # ---- OCR / Image Text Extraction ----

    def _extract_text_from_image(self, image_data: bytes) -> dict[str, Any]:
        """
        Extract text from an image.

        Uses PIL for basic image analysis. Full OCR requires Tesseract
        (pytesseract) which is used if available.
        """
        result: dict[str, Any] = {
            "text": "",
            "confidence": 0.0,
            "method": None,
            "image_info": {},
            "error": None,
        }

        try:
            from PIL import Image

            image = Image.open(io.BytesIO(image_data))
            result["image_info"] = {
                "format": image.format,
                "size": image.size,
                "mode": image.mode,
            }

            # Try pytesseract first
            try:
                import pytesseract

                text = pytesseract.image_to_string(image)
                result["text"] = text.strip()
                result["method"] = "tesseract"

                # Get confidence data
                try:
                    osd_data = pytesseract.image_to_data(
                        image, output_type=pytesseract.Output.DICT
                    )
                    confidences = [
                        int(c) for c in osd_data.get("conf", [])
                        if str(c).isdigit() and int(c) > 0
                    ]
                    if confidences:
                        result["confidence"] = sum(confidences) / len(confidences)
                except Exception:
                    result["confidence"] = 50.0 if result["text"] else 0.0

            except ImportError:
                # Fallback: basic image analysis without OCR
                result["method"] = "pil_basic"
                result["text"] = ""
                result["error"] = (
                    "pytesseract not installed. Install with: "
                    "pip install pytesseract (requires Tesseract binary)"
                )

                # Provide basic image analysis
                result["image_info"]["has_text_like_regions"] = (
                    self._detect_text_regions(image)
                )

        except ImportError:
            result["error"] = (
                "PIL/Pillow not installed. Install with: pip install Pillow"
            )
            result["method"] = "unavailable"

        except Exception as exc:
            result["error"] = f"Image text extraction failed: {str(exc)}"

        return result

    @staticmethod
    def _detect_text_regions(image: Any) -> bool:
        """
        Basic heuristic to detect if an image likely contains text.

        Uses contrast and edge analysis as a rough indicator.
        """
        try:
            # Convert to grayscale
            gray = image.convert("L")
            pixels = list(gray.getdata())

            if not pixels:
                return False

            # Calculate contrast (standard deviation of pixel values)
            mean = sum(pixels) / len(pixels)
            variance = sum((p - mean) ** 2 for p in pixels) / len(pixels)
            std_dev = variance ** 0.5

            # High contrast images are more likely to contain text
            return std_dev > 40

        except Exception:
            return False

    # ---- NLP Social Engineering Detection ----

    def _scan_patterns(
        self,
        text: str,
        patterns: list[tuple[str, float]],
        category: str,
    ) -> list[dict[str, Any]]:
        """Scan text against a list of weighted patterns."""
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()

        for pattern, weight in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0).strip()
                if matched_text.lower() not in seen:
                    seen.add(matched_text.lower())
                    findings.append({
                        "category": category,
                        "matched_text": matched_text,
                        "weight": weight,
                        "position": match.start(),
                    })

        return findings

    def _analyze_text_structure(self, text: str) -> dict[str, Any]:
        """Analyze text structure for phishing indicators."""
        analysis: dict[str, Any] = {
            "word_count": len(text.split()),
            "sentence_count": len(re.split(r"[.!?]+", text)),
            "has_urls": bool(re.search(r"https?://[^\s]+", text)),
            "has_email_addresses": bool(
                re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
            ),
            "has_phone_numbers": bool(
                re.search(r"[\+]?[\d\s\-\(\)]{7,15}", text)
            ),
            "exclamation_count": text.count("!"),
            "question_count": text.count("?"),
            "caps_ratio": 0.0,
            "url_count": len(re.findall(r"https?://[^\s]+", text)),
        }

        # Calculate caps ratio
        alpha_chars = [c for c in text if c.isalpha()]
        if alpha_chars:
            caps = sum(1 for c in alpha_chars if c.isupper())
            analysis["caps_ratio"] = round(caps / len(alpha_chars), 3)

        return analysis

    async def detect_social_engineering(self, text: str) -> dict[str, Any]:
        """
        Analyze text for social engineering and spear phishing patterns.

        Args:
            text: The text content to analyze.

        Returns:
            Dictionary with 'score', 'findings', and 'metadata' keys.
        """
        try:
            if not text or not isinstance(text, str):
                return {
                    "score": 0,
                    "findings": [],
                    "metadata": {"error": "Invalid or empty text provided"},
                }

            text = text.strip()
            all_findings: list[dict[str, Any]] = []

            # Scan all pattern categories
            pattern_categories = [
                (URGENCY_PHRASES, "urgency"),
                (AUTHORITY_PHRASES, "authority_impersonation"),
                (THREAT_PHRASES, "threat_language"),
                (CREDENTIAL_REQUEST_PHRASES, "credential_request"),
                (REWARD_PHRASES, "reward_lure"),
                (IMPERSONATION_PHRASES, "impersonation"),
                (SPEAR_PHISHING_INDICATORS, "spear_phishing"),
            ]

            category_scores: dict[str, float] = {}
            for patterns, category in pattern_categories:
                findings = self._scan_patterns(text, patterns, category)
                all_findings.extend(findings)
                if findings:
                    category_scores[category] = sum(
                        f["weight"] for f in findings
                    ) / len(findings)

            # Text structure analysis
            structure = self._analyze_text_structure(text)

            # Additional structural findings
            if structure["caps_ratio"] > 0.3:
                all_findings.append({
                    "category": "suspicious_formatting",
                    "matched_text": "Excessive capitalization",
                    "weight": 0.5,
                    "detail": f"Caps ratio: {structure['caps_ratio']:.1%}",
                })

            if structure["exclamation_count"] > 3:
                all_findings.append({
                    "category": "suspicious_formatting",
                    "matched_text": "Excessive exclamation marks",
                    "weight": 0.3,
                    "detail": f"Found {structure['exclamation_count']} exclamation marks",
                })

            if structure["url_count"] > 3:
                all_findings.append({
                    "category": "suspicious_content",
                    "matched_text": "Multiple URLs",
                    "weight": 0.4,
                    "detail": f"Text contains {structure['url_count']} URLs",
                })

            # Calculate composite score
            score = self._calculate_se_score(all_findings, category_scores)

            # Determine severity for each finding
            for finding in all_findings:
                weight = finding.get("weight", 0)
                if weight >= 0.8:
                    finding["severity"] = "high"
                elif weight >= 0.5:
                    finding["severity"] = "medium"
                else:
                    finding["severity"] = "low"

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
                    "text_length": len(text),
                    "structure": structure,
                    "category_scores": category_scores,
                    "categories_detected": list(category_scores.keys()),
                    "analysis_type": "social_engineering_detection",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"Social engineering detection failed: {str(exc)}",
                    "analysis_type": "social_engineering_detection",
                },
            }

    def _calculate_se_score(
        self,
        findings: list[dict[str, Any]],
        category_scores: dict[str, float],
    ) -> int:
        """Calculate a 0-100 social engineering risk score."""
        if not findings:
            return 0

        # Base score from weighted findings
        total_weight = sum(f.get("weight", 0) for f in findings)
        base_score = min(total_weight * 15, 60)

        # Bonus for multiple categories (compound attack indicators)
        category_bonus = 0
        num_categories = len(category_scores)
        if num_categories >= 4:
            category_bonus = 25
        elif num_categories >= 3:
            category_bonus = 15
        elif num_categories >= 2:
            category_bonus = 8

        # High-risk category bonus
        high_risk_categories = {"credential_request", "threat_language", "urgency"}
        high_risk_present = high_risk_categories & set(category_scores.keys())
        if len(high_risk_present) >= 2:
            category_bonus += 10

        return min(int(base_score + category_bonus), 100)

    # ---- Combined OCR + NLP Analysis ----

    async def analyze_text_image(self, image_data: bytes) -> dict[str, Any]:
        """
        Extract text from an image and analyze it for social engineering.

        Args:
            image_data: Raw image bytes.

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

            # Extract text from image
            ocr_result = self._extract_text_from_image(image_data)
            extracted_text = ocr_result.get("text", "")

            all_findings: list[dict[str, Any]] = []
            se_result: dict[str, Any] = {}

            if ocr_result.get("error"):
                all_findings.append({
                    "category": "ocr_status",
                    "severity": "low",
                    "detail": ocr_result["error"],
                })

            if extracted_text:
                # Run social engineering detection on extracted text
                se_result = await self.detect_social_engineering(extracted_text)
                all_findings.extend(se_result.get("findings", []))
            else:
                all_findings.append({
                    "category": "ocr_status",
                    "severity": "low",
                    "detail": "No text could be extracted from the image",
                })

            score = se_result.get("score", 0) if se_result else 0

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
                    "ocr_method": ocr_result.get("method"),
                    "ocr_confidence": ocr_result.get("confidence", 0),
                    "extracted_text": extracted_text[:2000] if extracted_text else "",
                    "extracted_text_length": len(extracted_text),
                    "image_info": ocr_result.get("image_info", {}),
                    "se_categories": se_result.get("metadata", {}).get(
                        "categories_detected", []
                    ),
                    "analysis_type": "ocr_nlp_analysis",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"OCR/NLP analysis failed: {str(exc)}",
                    "analysis_type": "ocr_nlp_analysis",
                },
            }


# Module-level singleton
ocr_nlp_analyzer = OCRNLPAnalyzer()


async def analyze_text_image(image_data: bytes) -> dict[str, Any]:
    """Module-level convenience function."""
    return await ocr_nlp_analyzer.analyze_text_image(image_data)


async def detect_social_engineering(text: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await ocr_nlp_analyzer.detect_social_engineering(text)
