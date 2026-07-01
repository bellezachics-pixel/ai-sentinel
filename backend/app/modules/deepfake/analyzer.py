"""
AI-Sentinel Deepfake Analyzer Module

Analyzes image and audio file metadata for manipulation signs and
synthetic media indicators. Provides heuristic-based detection without
requiring GPU-based ML models.
"""

from __future__ import annotations

import io
import struct
from typing import Any


# --- Known Deepfake Tool Signatures ---

DEEPFAKE_SOFTWARE_SIGNATURES: set[str] = {
    "faceswap", "deepfacelab", "faceapp", "reface", "zao",
    "deepfake", "fakeapp", "dfaker", "avatarify", "wav2lip",
    "synthesia", "d-id", "heygen", "resemble", "descript",
    "elevenlabs", "murf", "play.ht", "uberduck", "tortoise-tts",
}

SYNTHETIC_VOICE_INDICATORS: set[str] = {
    "tts", "text-to-speech", "synthesized", "generated",
    "artificial", "neural", "vocoder", "wavenet", "tacotron",
}


class DeepfakeAnalyzer:
    """Analyzes media files for deepfake and manipulation indicators."""

    # ---- Image Analysis ----

    def _analyze_image_metadata(self, image_data: bytes) -> dict[str, Any]:
        """Extract and analyze image metadata for manipulation signs."""
        metadata: dict[str, Any] = {
            "format": None,
            "size_bytes": len(image_data),
            "exif": {},
            "findings": [],
        }

        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_data))
            metadata["format"] = image.format
            metadata["dimensions"] = {"width": image.width, "height": image.height}
            metadata["mode"] = image.mode

            # Extract EXIF data
            exif_data = image.getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    try:
                        if isinstance(value, bytes):
                            value = value.decode("utf-8", errors="replace")
                        metadata["exif"][tag_name] = str(value)[:500]
                    except (TypeError, ValueError):
                        metadata["exif"][tag_name] = repr(value)[:500]

            # Check for manipulation indicators
            findings = self._check_image_manipulation(metadata, image)
            metadata["findings"] = findings

        except ImportError:
            metadata["findings"].append({
                "category": "analysis_limitation",
                "severity": "low",
                "detail": "PIL/Pillow not installed; limited image analysis available",
            })
            # Basic format detection from magic bytes
            metadata["format"] = self._detect_format_from_bytes(image_data)

        except Exception as exc:
            metadata["findings"].append({
                "category": "analysis_error",
                "severity": "low",
                "detail": f"Image metadata extraction failed: {str(exc)}",
            })

        return metadata

    def _check_image_manipulation(
        self, metadata: dict[str, Any], image: Any
    ) -> list[dict[str, Any]]:
        """Check image for signs of manipulation or deepfake generation."""
        findings: list[dict[str, Any]] = []
        exif = metadata.get("exif", {})

        # Check software field for known deepfake tools
        software = exif.get("Software", "").lower()
        for sig in DEEPFAKE_SOFTWARE_SIGNATURES:
            if sig in software:
                findings.append({
                    "category": "deepfake_indicator",
                    "pattern_type": "known_deepfake_software",
                    "severity": "critical",
                    "detail": f"Image was processed with known deepfake tool: {sig}",
                    "software": exif.get("Software", ""),
                })
                break

        # Missing EXIF data (AI-generated images often lack EXIF)
        if not exif:
            findings.append({
                "category": "deepfake_indicator",
                "pattern_type": "missing_exif",
                "severity": "medium",
                "detail": (
                    "Image has no EXIF metadata; AI-generated images "
                    "typically lack camera metadata"
                ),
            })
        else:
            # Check for missing camera-specific fields
            camera_fields = ["Make", "Model", "LensModel", "FocalLength"]
            missing_camera = [f for f in camera_fields if f not in exif]
            if len(missing_camera) == len(camera_fields) and exif:
                findings.append({
                    "category": "deepfake_indicator",
                    "pattern_type": "no_camera_info",
                    "severity": "medium",
                    "detail": "Image has metadata but no camera information",
                })

            # Check for inconsistent timestamps
            date_fields = ["DateTime", "DateTimeOriginal", "DateTimeDigitized"]
            dates = {f: exif[f] for f in date_fields if f in exif}
            if len(dates) >= 2:
                unique_dates = set(dates.values())
                if len(unique_dates) > 1:
                    findings.append({
                        "category": "manipulation_indicator",
                        "pattern_type": "timestamp_inconsistency",
                        "severity": "medium",
                        "detail": "Image has inconsistent date/time stamps",
                        "dates": dates,
                    })

        # Check for unusual dimensions (perfect squares, very specific ratios)
        dims = metadata.get("dimensions", {})
        width = dims.get("width", 0)
        height = dims.get("height", 0)
        if width and height:
            # Common AI generation sizes
            ai_sizes = [
                (512, 512), (768, 768), (1024, 1024), (256, 256),
                (512, 768), (768, 512), (1024, 768), (768, 1024),
                (1024, 1792), (1792, 1024),
            ]
            if (width, height) in ai_sizes:
                findings.append({
                    "category": "deepfake_indicator",
                    "pattern_type": "ai_typical_dimensions",
                    "severity": "low",
                    "detail": (
                        f"Image dimensions ({width}x{height}) match common "
                        "AI generation sizes"
                    ),
                })

        # Check for PNG with no transparency but saved as PNG
        # (AI tools often output PNG unnecessarily)
        fmt = metadata.get("format", "")
        mode = metadata.get("mode", "")
        if fmt == "PNG" and mode == "RGB" and not exif:
            findings.append({
                "category": "deepfake_indicator",
                "pattern_type": "png_no_transparency_no_exif",
                "severity": "low",
                "detail": "PNG image with no transparency and no EXIF; common in AI output",
            })

        # Check for C2PA / Content Credentials
        # (Legitimate AI-generated images may include these)
        description = exif.get("ImageDescription", "").lower()
        user_comment = exif.get("UserComment", "").lower()
        for field in [description, user_comment, software]:
            if any(
                kw in field
                for kw in ["ai generated", "artificial intelligence", "stable diffusion",
                           "midjourney", "dall-e", "dalle", "generated by"]
            ):
                findings.append({
                    "category": "deepfake_indicator",
                    "pattern_type": "ai_generation_marker",
                    "severity": "high",
                    "detail": "Image metadata contains AI generation markers",
                })
                break

        return findings

    # ---- Audio Analysis ----

    def _analyze_audio_metadata(self, audio_data: bytes) -> dict[str, Any]:
        """Extract and analyze audio file metadata for synthetic voice indicators."""
        metadata: dict[str, Any] = {
            "format": None,
            "size_bytes": len(audio_data),
            "properties": {},
            "findings": [],
        }

        # Detect format from magic bytes
        fmt = self._detect_format_from_bytes(audio_data)
        metadata["format"] = fmt

        try:
            if fmt == "WAV":
                metadata["properties"] = self._parse_wav_header(audio_data)
            elif fmt == "MP3":
                metadata["properties"] = self._parse_mp3_basic(audio_data)

            # Check for synthetic voice indicators
            findings = self._check_audio_manipulation(metadata, audio_data)
            metadata["findings"] = findings

        except Exception as exc:
            metadata["findings"].append({
                "category": "analysis_error",
                "severity": "low",
                "detail": f"Audio metadata extraction failed: {str(exc)}",
            })

        return metadata

    def _parse_wav_header(self, data: bytes) -> dict[str, Any]:
        """Parse WAV file header for audio properties."""
        props: dict[str, Any] = {}
        if len(data) < 44:
            return props

        try:
            # RIFF header
            if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
                props["format"] = "WAV/RIFF"
                # fmt chunk
                fmt_offset = data.find(b"fmt ")
                if fmt_offset >= 0 and len(data) > fmt_offset + 24:
                    audio_format = struct.unpack_from("<H", data, fmt_offset + 8)[0]
                    channels = struct.unpack_from("<H", data, fmt_offset + 10)[0]
                    sample_rate = struct.unpack_from("<I", data, fmt_offset + 12)[0]
                    byte_rate = struct.unpack_from("<I", data, fmt_offset + 16)[0]
                    bits_per_sample = struct.unpack_from("<H", data, fmt_offset + 22)[0]

                    props["audio_format"] = audio_format
                    props["channels"] = channels
                    props["sample_rate"] = sample_rate
                    props["byte_rate"] = byte_rate
                    props["bits_per_sample"] = bits_per_sample

                    # Calculate duration
                    data_offset = data.find(b"data")
                    if data_offset >= 0 and len(data) > data_offset + 8:
                        data_size = struct.unpack_from("<I", data, data_offset + 4)[0]
                        if byte_rate > 0:
                            props["duration_seconds"] = round(data_size / byte_rate, 2)
        except (struct.error, IndexError):
            pass

        return props

    def _parse_mp3_basic(self, data: bytes) -> dict[str, Any]:
        """Parse basic MP3 properties."""
        props: dict[str, Any] = {"format": "MP3"}

        # Check for ID3 tag
        if data[:3] == b"ID3":
            props["has_id3"] = True
            # ID3v2 version
            if len(data) > 4:
                props["id3_version"] = f"2.{data[3]}.{data[4]}"

            # Try to extract text frames
            try:
                text = data[:4096].decode("utf-8", errors="replace")
                for sig in DEEPFAKE_SOFTWARE_SIGNATURES | SYNTHETIC_VOICE_INDICATORS:
                    if sig in text.lower():
                        props["suspicious_tag_content"] = sig
                        break
            except (UnicodeDecodeError, ValueError):
                pass
        else:
            props["has_id3"] = False

        return props

    def _check_audio_manipulation(
        self, metadata: dict[str, Any], audio_data: bytes
    ) -> list[dict[str, Any]]:
        """Check audio for signs of synthetic generation."""
        findings: list[dict[str, Any]] = []
        props = metadata.get("properties", {})

        # Check for suspicious tag content
        suspicious_tag = props.get("suspicious_tag_content")
        if suspicious_tag:
            findings.append({
                "category": "deepfake_indicator",
                "pattern_type": "synthetic_voice_marker",
                "severity": "high",
                "detail": f"Audio metadata contains synthetic voice indicator: {suspicious_tag}",
            })

        # Check for unusual sample rates (TTS often uses specific rates)
        sample_rate = props.get("sample_rate")
        tts_sample_rates = {16000, 22050, 24000}
        if sample_rate in tts_sample_rates:
            findings.append({
                "category": "deepfake_indicator",
                "pattern_type": "tts_sample_rate",
                "severity": "low",
                "detail": (
                    f"Audio sample rate ({sample_rate} Hz) is commonly used "
                    "by text-to-speech systems"
                ),
            })

        # Check for mono audio (TTS often outputs mono)
        channels = props.get("channels")
        if channels == 1:
            findings.append({
                "category": "deepfake_indicator",
                "pattern_type": "mono_audio",
                "severity": "low",
                "detail": "Audio is mono channel, common in synthesized speech",
            })

        # Check for very short or very uniform audio
        duration = props.get("duration_seconds")
        if duration is not None and duration < 1.0:
            findings.append({
                "category": "deepfake_indicator",
                "pattern_type": "very_short_audio",
                "severity": "low",
                "detail": f"Audio is very short ({duration}s), may be a synthesized clip",
            })

        # Scan raw bytes for TTS engine signatures
        try:
            header_text = audio_data[:8192].decode("utf-8", errors="replace").lower()
            for indicator in SYNTHETIC_VOICE_INDICATORS:
                if indicator in header_text:
                    findings.append({
                        "category": "deepfake_indicator",
                        "pattern_type": "tts_engine_signature",
                        "severity": "high",
                        "detail": f"Audio contains TTS engine signature: {indicator}",
                    })
                    break
        except (UnicodeDecodeError, ValueError):
            pass

        return findings

    # ---- Utility Methods ----

    @staticmethod
    def _detect_format_from_bytes(data: bytes) -> str | None:
        """Detect file format from magic bytes."""
        if len(data) < 12:
            return None

        # Image formats
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return "PNG"
        if data[:2] == b"\xff\xd8":
            return "JPEG"
        if data[:4] == b"GIF8":
            return "GIF"
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return "WEBP"
        if data[:4] in (b"II\x2a\x00", b"MM\x00\x2a"):
            return "TIFF"
        if data[:4] == b"\x00\x00\x01\x00":
            return "ICO"

        # Audio formats
        if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
            return "WAV"
        if data[:3] == b"ID3" or data[:2] == b"\xff\xfb":
            return "MP3"
        if data[:4] == b"fLaC":
            return "FLAC"
        if data[:4] == b"OggS":
            return "OGG"
        if data[4:8] == b"ftyp":
            return "MP4/M4A"

        return "UNKNOWN"

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

    # ---- Public API ----

    async def analyze_media(
        self, file_data: bytes, media_type: str
    ) -> dict[str, Any]:
        """
        Analyze a media file for deepfake and manipulation indicators.

        Args:
            file_data: Raw file bytes.
            media_type: One of "image", "audio", or "auto".

        Returns:
            Dictionary with 'score', 'findings', and 'metadata' keys.
        """
        try:
            if not file_data:
                return {
                    "score": 0,
                    "findings": [],
                    "metadata": {"error": "No file data provided"},
                }

            # Auto-detect media type if needed
            if media_type == "auto":
                detected_format = self._detect_format_from_bytes(file_data)
                if detected_format in ("PNG", "JPEG", "GIF", "WEBP", "TIFF", "ICO"):
                    media_type = "image"
                elif detected_format in ("WAV", "MP3", "FLAC", "OGG", "MP4/M4A"):
                    media_type = "audio"
                else:
                    return {
                        "score": 0,
                        "findings": [{
                            "category": "analysis_limitation",
                            "severity": "low",
                            "detail": (
                                f"Could not determine media type "
                                f"(detected format: {detected_format})"
                            ),
                        }],
                        "metadata": {
                            "detected_format": detected_format,
                            "analysis_type": "deepfake_analysis",
                        },
                    }

            if media_type == "image":
                analysis = self._analyze_image_metadata(file_data)
            elif media_type == "audio":
                analysis = self._analyze_audio_metadata(file_data)
            else:
                return {
                    "score": 0,
                    "findings": [],
                    "metadata": {
                        "error": f"Unsupported media type: {media_type}",
                        "analysis_type": "deepfake_analysis",
                    },
                }

            all_findings = analysis.get("findings", [])
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
                    "media_type": media_type,
                    "format": analysis.get("format"),
                    "size_bytes": len(file_data),
                    "properties": analysis.get("properties", {}),
                    "exif": analysis.get("exif", {}),
                    "dimensions": analysis.get("dimensions"),
                    "analysis_type": "deepfake_analysis",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"Deepfake analysis failed: {str(exc)}",
                    "media_type": media_type,
                    "analysis_type": "deepfake_analysis",
                },
            }


# Module-level singleton
deepfake_analyzer = DeepfakeAnalyzer()


async def analyze_media(file_data: bytes, media_type: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await deepfake_analyzer.analyze_media(file_data, media_type)
