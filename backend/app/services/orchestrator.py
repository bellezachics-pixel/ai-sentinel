"""
Analysis Orchestrator - Coordina todos los módulos de análisis
Lazy-loading para startup rápido en Render Free tier
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from datetime import datetime
from typing import Optional

from app.models.schemas import (
    AnalysisResult,
    AnalysisType,
    RiskScore,
    ThreatIntelResult,
)
from app.core.config import settings
from app.core.url_safety import normalize_public_http_url
from app.services.risk_engine import risk_engine


class AnalysisOrchestrator:
    def __init__(self):
        self._url_analyzer = None
        self._content_analyzer = None
        self._header_analyzer = None
        self._network_analyzer = None
        self._threat_intel = None
        self._qrishing_analyzer = None
        self._deepfake_analyzer = None
        self._ocr_nlp_analyzer = None
        self._identity_client = None
        self._analysis_history: list[AnalysisResult] = []

    @property
    def url_analyzer(self):
        if self._url_analyzer is None:
            from app.modules.url_analyzer.analyzer import URLAnalyzer
            self._url_analyzer = URLAnalyzer()
        return self._url_analyzer

    @property
    def content_analyzer(self):
        if self._content_analyzer is None:
            from app.modules.content_analyzer.analyzer import ContentAnalyzer
            self._content_analyzer = ContentAnalyzer()
        return self._content_analyzer

    @property
    def header_analyzer(self):
        if self._header_analyzer is None:
            from app.modules.header_analyzer.analyzer import HeaderAnalyzer
            self._header_analyzer = HeaderAnalyzer()
        return self._header_analyzer

    @property
    def network_analyzer(self):
        if self._network_analyzer is None:
            from app.modules.network_analyzer.analyzer import NetworkAnalyzer
            self._network_analyzer = NetworkAnalyzer()
        return self._network_analyzer

    @property
    def threat_intel(self):
        if self._threat_intel is None:
            from app.modules.threat_intel.provider import ThreatIntelProvider
            self._threat_intel = ThreatIntelProvider()
        return self._threat_intel

    @property
    def qrishing_analyzer(self):
        if self._qrishing_analyzer is None:
            from app.modules.qrishing.analyzer import QRishingAnalyzer
            self._qrishing_analyzer = QRishingAnalyzer()
        return self._qrishing_analyzer

    @property
    def deepfake_analyzer(self):
        if self._deepfake_analyzer is None:
            from app.modules.deepfake.analyzer import DeepfakeAnalyzer
            self._deepfake_analyzer = DeepfakeAnalyzer()
        return self._deepfake_analyzer

    @property
    def ocr_nlp_analyzer(self):
        if self._ocr_nlp_analyzer is None:
            from app.modules.ocr_nlp.analyzer import OCRNLPAnalyzer
            self._ocr_nlp_analyzer = OCRNLPAnalyzer()
        return self._ocr_nlp_analyzer

    @property
    def identity_client(self):
        if self._identity_client is None:
            from app.modules.identity.hibp_client import HIBPClient
            self._identity_client = HIBPClient()
        return self._identity_client

    async def analyze_url(self, url: str, deep_scan: bool = False) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]
        safe_url, safety_finding = normalize_public_http_url(url)

        url_result = await self.url_analyzer.analyze_url(safe_url or url)
        header_result = {"score": 0, "findings": []}
        network_result = {"score": 0, "findings": []}
        intel_results = []
        if safety_finding:
            header_result = {
                "score": 75 if safety_finding.get("severity") == "high" else 35,
                "findings": [safety_finding],
                "metadata": {"analysis_type": "network_safety"},
            }
        else:
            tasks = [self.header_analyzer.analyze_headers(safe_url or url)]
            if deep_scan:
                tasks.append(self.network_analyzer.check_network_integrity(safe_url or url))
                tasks.append(self.threat_intel.query_all(safe_url or url, "url"))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            if results and not isinstance(results[0], Exception):
                header_result = results[0]
            if deep_scan and len(results) > 1:
                if not isinstance(results[1], Exception):
                    network_result = results[1]
                if len(results) > 2 and not isinstance(results[2], Exception):
                    intel_results = results[2]

        # Content analysis (fetch page content) - SSRF-safe
        content_result = {"score": 0, "findings": []}
        if safe_url and not safety_finding:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=True) as client:
                    resp = await client.get(safe_url)
                    content_result = await self.content_analyzer.analyze_content(resp.text, "html")
            except Exception:
                pass

        # Calculate risk score
        intel_scores = [r.get("score", 0) for r in intel_results] if intel_results else []
        risk_score = risk_engine.calculate_risk(
            url_score=url_result.get("score", 0),
            content_score=content_result.get("score", 0),
            header_score=header_result.get("score", 0),
            network_score=network_result.get("score", 0),
            threat_intel_scores=intel_scores,
        )

        # Aggregate findings
        all_findings = []
        for source, result in [
            ("url_analysis", url_result),
            ("content_analysis", content_result),
            ("header_analysis", header_result),
            ("network_analysis", network_result),
        ]:
            for f in result.get("findings", []):
                f["source"] = source
                all_findings.append(f)

        # Build threat intel results
        threat_intel_models = [
            ThreatIntelResult(
                source=r.get("source", "unknown"),
                score=r.get("score", 0),
                is_malicious=r.get("is_malicious", False),
                details=r.get("details", {}),
            )
            for r in intel_results
        ]

        # Generate recommendations
        recommendations = self._generate_recommendations(risk_score, all_findings)

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.URL,
            target=url,
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=all_findings,
            threat_intel=threat_intel_models,
            recommendations=recommendations,
            metadata={
                "deep_scan": deep_scan,
                "modules_executed": ["url", "content", "headers"]
                + (["network", "threat_intel"] if deep_scan else []),
            },
        )

        self._analysis_history.append(result)
        return result

    async def analyze_email(self, subject: str, sender: str, body: str, headers: dict | None = None) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]

        # NLP analysis for social engineering
        nlp_result = await self.ocr_nlp_analyzer.detect_social_engineering(body)

        # Content analysis
        content_result = await self.content_analyzer.analyze_content(body, "text")

        # Check sender domain
        url_score = 0
        url_findings = []
        if "@" in sender:
            domain = sender.split("@")[1]
            url_result = await self.url_analyzer.analyze_url(f"https://{domain}")
            url_score = url_result.get("score", 0) * 0.5
            url_findings = url_result.get("findings", [])

        risk_score = risk_engine.calculate_risk(
            url_score=url_score,
            content_score=max(content_result.get("score", 0), nlp_result.get("score", 0)),
        )

        all_findings = []
        for f in nlp_result.get("findings", []):
            f["source"] = "nlp_analysis"
            all_findings.append(f)
        for f in content_result.get("findings", []):
            f["source"] = "content_analysis"
            all_findings.append(f)
        for f in url_findings:
            f["source"] = "sender_analysis"
            all_findings.append(f)

        recommendations = self._generate_recommendations(risk_score, all_findings)

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.EMAIL,
            target=sender,
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=all_findings,
            recommendations=recommendations,
            metadata={"subject": subject, "sender": sender},
        )

        self._analysis_history.append(result)
        return result

    async def analyze_message(self, platform: str, body: str) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]
        platform = (platform or "message").strip().lower()

        nlp_result = await self.ocr_nlp_analyzer.detect_social_engineering(body)
        content_result = await self.content_analyzer.analyze_content(body, "text")
        ai_result = await self._analyze_message_with_openai(platform, body)

        content_score = max(
            content_result.get("score", 0),
            nlp_result.get("score", 0),
            ai_result.get("score", 0),
        )
        risk_score = risk_engine.calculate_risk(content_score=content_score)

        all_findings = []
        for source, result in [
            ("nlp_analysis", nlp_result),
            ("content_analysis", content_result),
            ("openai_analysis", ai_result),
        ]:
            for finding in result.get("findings", []):
                normalized = self._normalize_finding(finding)
                normalized["source"] = source
                all_findings.append(normalized)

        recommendations = self._generate_recommendations(risk_score, all_findings)
        if ai_result.get("recommendation"):
            recommendations.insert(0, ai_result["recommendation"])

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.MESSAGE,
            target=platform,
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=all_findings,
            recommendations=recommendations,
            metadata={
                "platform": platform,
                "message_length": len(body),
                "openai_used": ai_result.get("provider") == "openai",
                "modules_executed": ["nlp", "content"]
                + (["openai"] if ai_result.get("provider") == "openai" else []),
            },
        )

        self._analysis_history.append(result)
        return result

    async def analyze_qr(self, image_data: bytes) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]

        qr_result = await self.qrishing_analyzer.analyze_qr(image_data)

        risk_score = risk_engine.calculate_risk(
            url_score=qr_result.get("score", 0),
        )

        findings = qr_result.get("findings", [])
        for f in findings:
            f["source"] = "qrishing_analysis"

        recommendations = self._generate_recommendations(risk_score, findings)

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.QR_CODE,
            target="qr_code_image",
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=findings,
            recommendations=recommendations,
            metadata=qr_result.get("metadata", {}),
        )

        self._analysis_history.append(result)
        return result

    async def analyze_media(self, file_data: bytes, media_type: str) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]

        deepfake_result = await self.deepfake_analyzer.analyze_media(file_data, media_type)

        risk_score = risk_engine.calculate_risk(
            content_score=deepfake_result.get("score", 0),
        )

        findings = deepfake_result.get("findings", [])
        for f in findings:
            f["source"] = "deepfake_analysis"

        recommendations = self._generate_recommendations(risk_score, findings)

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.DEEPFAKE,
            target=f"media_file.{media_type}",
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=findings,
            recommendations=recommendations,
            metadata=deepfake_result.get("metadata", {}),
        )

        self._analysis_history.append(result)
        return result

    async def analyze_file(
        self,
        file_data: bytes,
        filename: str,
        content_type: str,
    ) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]
        filename = filename or "archivo_desconocido"
        content_type = content_type or "application/octet-stream"
        size = len(file_data)
        sha256 = hashlib.sha256(file_data).hexdigest()
        extension = os.path.splitext(filename.lower())[1].lstrip(".") or "unknown"

        local_findings = self._analyze_file_locally(filename, extension, size, content_type)
        vt_results = await self.threat_intel.query_all(sha256, "hash")
        vt_findings, vt_score = self._findings_from_virustotal(vt_results)

        file_score = max(self._score_file_findings(local_findings), vt_score)
        risk_score = risk_engine.calculate_risk(content_score=file_score)

        findings = local_findings + vt_findings
        recommendations = self._generate_recommendations(risk_score, findings)
        if not any(r.get("available") for r in vt_results):
            recommendations.append(
                "Configura VIRUSTOTAL_API_KEY para consultar reputacion real por hash."
            )

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.FILE,
            target=filename,
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=findings,
            recommendations=recommendations,
            metadata={
                "filename": filename,
                "content_type": content_type,
                "extension": extension,
                "size_bytes": size,
                "sha256": sha256,
                "virustotal_available": any(r.get("available") for r in vt_results),
                "virustotal_results": vt_results,
            },
        )

        self._analysis_history.append(result)
        return result

    async def check_network(self, target: str | None = None) -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]
        target = target or "8.8.8.8"

        network_result = await self.network_analyzer.check_network_integrity(target)

        risk_score = risk_engine.calculate_risk(
            network_score=network_result.get("score", 0),
        )

        findings = network_result.get("findings", [])
        for f in findings:
            f["source"] = "network_analysis"

        recommendations = self._generate_recommendations(risk_score, findings)

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.NETWORK,
            target=target,
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=findings,
            recommendations=recommendations,
            metadata=network_result.get("metadata", {}),
        )

        self._analysis_history.append(result)
        return result

    async def check_identity(self, value: str, check_type: str = "email") -> AnalysisResult:
        analysis_id = str(uuid.uuid4())[:8]

        if check_type == "email":
            hibp_result = await self.identity_client.check_email(value)
        elif check_type == "password":
            hibp_result = await self.identity_client.check_password(value)
        elif check_type == "username":
            hibp_result = await self.identity_client.check_username(value)
        elif check_type == "phone":
            hibp_result = await self.identity_client.check_phone(value)
        else:
            hibp_result = {"error": "Tipo de verificación no soportado", "found": False, "breaches": []}

        error = hibp_result.get("error")
        found = hibp_result.get("found", False)
        breaches = hibp_result.get("breaches", [])

        findings = []
        if error:
            findings.append({
                "type": "identity_check_error",
                "severity": "medium",
                "description": error,
                "source": "hibp",
            })
        elif found:
            for breach in breaches:
                findings.append({
                    "type": "breach_found",
                    "severity": "high",
                    "description": f"{breach['name']} ({breach['date']}): datos expuestos: {', '.join(breach['data'])}",
                    "source": "hibp",
                    "details": breach,
                })
        else:
            findings.append({
                "type": "no_breach_found",
                "severity": "low",
                "description": hibp_result.get("message", "No se encontraron filtraciones"),
                "source": "hibp",
            })

        risk_score = risk_engine.calculate_risk(
            content_score=75 if found else 0,
        )

        recommendations = self._generate_recommendations(risk_score, findings)
        if found:
            recommendations.extend([
                "Cambia tu contraseña inmediatamente en los servicios afectados.",
                "Activa la autenticación de dos factores (2FA).",
                "No reutilices contraseñas entre servicios.",
            ])

        result = AnalysisResult(
            id=analysis_id,
            analysis_type=AnalysisType.FULL_SCAN,
            target=value,
            timestamp=datetime.utcnow(),
            risk_score=risk_score,
            findings=findings,
            recommendations=recommendations,
            metadata={
                "check_type": check_type,
                "hibp_result": hibp_result,
                "breaches": breaches,
            },
        )

        self._analysis_history.append(result)
        return result

    @staticmethod
    def _analyze_file_locally(
        filename: str,
        extension: str,
        size: int,
        content_type: str,
    ) -> list[dict]:
        findings: list[dict] = []
        executable_exts = {"exe", "msi", "bat", "cmd", "scr", "ps1", "app", "dmg", "apk"}
        archive_exts = {"zip", "rar", "7z", "tar", "gz"}
        document_exts = {"doc", "docm", "xlsm", "pptm"}

        if extension in executable_exts:
            findings.append({
                "type": "archivo ejecutable",
                "severity": "medium",
                "description": "El archivo puede ejecutar codigo en el dispositivo. Verifica su origen antes de abrirlo.",
            })
        if extension in archive_exts:
            findings.append({
                "type": "archivo comprimido",
                "severity": "low",
                "description": "Los comprimidos pueden ocultar multiples archivos o evadir revisiones simples.",
            })
        if extension in document_exts:
            findings.append({
                "type": "documento con macros",
                "severity": "high",
                "description": "Este tipo de documento puede contener macros usadas para malware o phishing.",
            })
        if size > 100 * 1024 * 1024:
            findings.append({
                "type": "archivo grande",
                "severity": "low",
                "description": "El archivo supera 100 MB; algunas APIs pueden limitar analisis completos.",
            })
        if extension == "unknown" or not content_type:
            findings.append({
                "type": "tipo desconocido",
                "severity": "low",
                "description": f"No se pudo confirmar claramente el tipo de archivo: {filename}.",
            })

        return findings

    @staticmethod
    def _score_file_findings(findings: list[dict]) -> int:
        weights = {"critical": 75, "high": 50, "medium": 30, "low": 10}
        return min(100, max((weights.get(f.get("severity", "low"), 10) for f in findings), default=0))

    @staticmethod
    def _findings_from_virustotal(results: list[dict]) -> tuple[list[dict], int]:
        findings: list[dict] = []
        score = 0

        for result in results:
            if result.get("provider") != "virustotal":
                continue
            if result.get("error"):
                findings.append({
                    "type": "virustotal no disponible",
                    "severity": "low",
                    "description": str(result["error"]),
                    "source": "virustotal",
                })
                continue

            data = result.get("data", {})
            if data.get("found") is False:
                findings.append({
                    "type": "hash no encontrado",
                    "severity": "low",
                    "description": "VirusTotal no tiene reputacion previa para este hash.",
                    "source": "virustotal",
                })
                continue

            stats = data.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            total = sum(int(v or 0) for v in stats.values()) if stats else 0

            if malicious > 0:
                score = min(100, 70 + malicious * 5)
                findings.append({
                    "type": "deteccion virustotal",
                    "severity": "critical" if malicious >= 5 else "high",
                    "description": f"VirusTotal reporta {malicious}/{total} motores maliciosos para este hash.",
                    "source": "virustotal",
                    "details": data,
                })
            elif suspicious > 0:
                score = max(score, 45)
                findings.append({
                    "type": "sospechoso virustotal",
                    "severity": "medium",
                    "description": f"VirusTotal reporta {suspicious}/{total} motores sospechosos.",
                    "source": "virustotal",
                    "details": data,
                })
            elif result.get("available"):
                findings.append({
                    "type": "sin detecciones virustotal",
                    "severity": "low",
                    "description": "VirusTotal no reporta detecciones maliciosas para este hash.",
                    "source": "virustotal",
                    "details": data,
                })

        return findings, score

    async def get_dashboard_stats(self) -> dict:
        total = len(self._analysis_history)
        threats = sum(1 for a in self._analysis_history if a.risk_score.level in ("high", "critical"))
        distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in self._analysis_history:
            distribution[a.risk_score.level.value] += 1

        recent = sorted(self._analysis_history, key=lambda x: x.timestamp, reverse=True)[:10]

        # Network status check
        try:
            net_result = await self.network_analyzer.check_network_integrity("8.8.8.8")
            network_secure = net_result.get("score", 0) < 25
        except Exception:
            network_secure = True

        return {
            "total_scans": total,
            "threats_detected": threats,
            "active_monitors": 3,
            "risk_distribution": distribution,
            "recent_analyses": [r.model_dump() for r in recent],
            "network_status": {
                "is_secure": network_secure,
                "risk_indicators": [],
            },
        }

    def _generate_recommendations(self, risk_score: RiskScore, findings: list[dict]) -> list[str]:
        recommendations = []
        level = risk_score.level.value if hasattr(risk_score.level, "value") else risk_score.level

        if level == "critical":
            recommendations.append("ALERTA CRITICA: No interactuar con este recurso. Posible ataque confirmado.")
            recommendations.append("Reportar inmediatamente al equipo de seguridad.")
            recommendations.append("Bloquear la URL/IP en el firewall corporativo.")
        elif level == "high":
            recommendations.append("PRECAUCION: Alto riesgo detectado. Se recomienda no interactuar.")
            recommendations.append("Verificar la autenticidad del recurso por canales alternativos.")
        elif level == "medium":
            recommendations.append("Hallazgos menores detectados. Proceder con precaucion.")
            recommendations.append("Verificar que el sitio sea el oficial antes de ingresar credenciales.")
        else:
            recommendations.append("No se detectaron amenazas significativas.")

        # Specific recommendations based on findings
        finding_types = {f.get("type", "") for f in findings}
        if "aitm_proxy" in finding_types or "tls_anomaly" in finding_types:
            recommendations.append("Posible proxy AiTM detectado. Verificar certificado TLS manualmente.")
        if "credential_harvesting" in finding_types:
            recommendations.append("Formulario de recoleccion de credenciales detectado. No ingresar datos.")
        if "social_engineering" in finding_types:
            recommendations.append("Patrones de ingenieria social detectados. Verificar el remitente.")

        return recommendations

    @staticmethod
    def _normalize_finding(finding: dict) -> dict:
        finding_type = (
            finding.get("type")
            or finding.get("pattern_type")
            or finding.get("category")
            or "hallazgo"
        )
        description = (
            finding.get("description")
            or finding.get("detail")
            or finding.get("matched_text")
            or str(finding_type)
        )
        severity = finding.get("severity", "low")

        return {
            **finding,
            "type": str(finding_type).replace("_", " "),
            "description": str(description),
            "severity": severity,
        }

    async def _analyze_message_with_openai(self, platform: str, body: str) -> dict:
        if not settings.OPENAI_API_KEY:
            return {"score": 0, "findings": [], "provider": "local"}

        try:
            import json
            import httpx

            prompt = (
                "Analiza este mensaje por phishing, fraude, extorsion, robo de cuentas "
                "o ingenieria social. Responde solo JSON valido con: "
                "score entero 0-100, severity low|medium|high|critical, "
                "reason texto breve, recommendation texto breve. "
                f"Plataforma: {platform}. Mensaje: {body[:4000]}"
            )
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": settings.OPENAI_CHAT_MODEL,
                        "messages": [
                            {
                                "role": "system",
                                "content": "Eres un analista de ciberseguridad. Responde solo JSON.",
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 300,
                    },
                )
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                data = json.loads(content)

            score = max(0, min(100, int(data.get("score", 0))))
            if score == 0:
                return {"score": 0, "findings": [], "provider": "openai"}

            return {
                "score": score,
                "provider": "openai",
                "recommendation": str(data.get("recommendation", "")),
                "findings": [
                    {
                        "type": "analisis ia",
                        "severity": str(data.get("severity", "medium")),
                        "description": str(data.get("reason", "Riesgo detectado por IA")),
                    }
                ],
            }
        except Exception:
            return {"score": 0, "findings": [], "provider": "local_fallback"}


orchestrator = AnalysisOrchestrator()
