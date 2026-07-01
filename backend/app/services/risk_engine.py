"""
Risk Engine - Motor de Riesgo AI-Sentinel
Score Final = (Peso_URL * Score_URL) + (Peso_Contenido * Score_Contenido) +
              (Peso_Cabeceras * Score_Cabeceras) + (Peso_Red * Score_Intervencion_Red)
"""
from __future__ import annotations
from typing import Optional, List
from app.core.config import settings
from app.models.schemas import RiskScore, RiskLevel


class RiskEngine:
    def __init__(self):
        self.weight_url = settings.WEIGHT_URL
        self.weight_content = settings.WEIGHT_CONTENT
        self.weight_headers = settings.WEIGHT_HEADERS
        self.weight_network = settings.WEIGHT_NETWORK

    def calculate_risk(
        self,
        url_score: float = 0,
        content_score: float = 0,
        header_score: float = 0,
        network_score: float = 0,
        threat_intel_scores: Optional[List[float]] = None,
    ) -> RiskScore:
        base_score = (
            self.weight_url * url_score
            + self.weight_content * content_score
            + self.weight_headers * header_score
            + self.weight_network * network_score
        )

        # Boost from threat intelligence
        intel_boost = 0.0
        if threat_intel_scores:
            avg_intel = sum(threat_intel_scores) / len(threat_intel_scores)
            intel_boost = avg_intel * 0.15  # 15% boost from TI

        total = min(100, base_score + intel_boost)

        level = self._classify_risk(total)

        breakdown = {
            "url": {"score": round(url_score, 1), "weight": self.weight_url, "weighted": round(self.weight_url * url_score, 1)},
            "content": {"score": round(content_score, 1), "weight": self.weight_content, "weighted": round(self.weight_content * content_score, 1)},
            "headers": {"score": round(header_score, 1), "weight": self.weight_headers, "weighted": round(self.weight_headers * header_score, 1)},
            "network": {"score": round(network_score, 1), "weight": self.weight_network, "weighted": round(self.weight_network * network_score, 1)},
            "threat_intel_boost": round(intel_boost, 1),
        }

        return RiskScore(
            total=round(total, 1),
            url_score=round(url_score, 1),
            content_score=round(content_score, 1),
            header_score=round(header_score, 1),
            network_score=round(network_score, 1),
            level=level,
            breakdown=breakdown,
        )

    def _classify_risk(self, score: float) -> RiskLevel:
        if score < 25:
            return RiskLevel.LOW
        elif score < 50:
            return RiskLevel.MEDIUM
        elif score < 75:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL


risk_engine = RiskEngine()
