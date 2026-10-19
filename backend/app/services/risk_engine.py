"""
Risk Engine - Motor de Riesgo Guardia Flow
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
        url_score: Optional[float] = None,
        content_score: Optional[float] = None,
        header_score: Optional[float] = None,
        network_score: Optional[float] = None,
        threat_intel_scores: Optional[List[float]] = None,
    ) -> RiskScore:
        """
        Score normalizado sobre los modulos REALMENTE ejecutados.

        Un modulo con score None significa «no analizado» y se excluye del
        calculo (sus pesos se redistribuyen entre los ejecutados). Un
        modulo con score 0 significa «analizado sin hallazgos» y SÍ pesa.
        Asi, un analisis de solo mensajes con contenido 100/100 da 100
        (critico), no 25 (medio): las senales extremas ya no se diluyen.
        """
        executed = [
            (self.weight_url, url_score),
            (self.weight_content, content_score),
            (self.weight_headers, header_score),
            (self.weight_network, network_score),
        ]
        executed = [(w, s) for w, s in executed if s is not None]

        if executed:
            total_weight = sum(w for w, _ in executed)
            base_score = sum(w * s for w, s in executed) / total_weight
        else:
            base_score = 0.0

        # Boost from threat intelligence (solo si aporto inteligencia real)
        intel_boost = 0.0
        if threat_intel_scores:
            avg_intel = sum(threat_intel_scores) / len(threat_intel_scores)
            intel_boost = avg_intel * 0.15  # 15% boost from TI

        total = min(100, base_score + intel_boost)

        level = self._classify_risk(total)

        def _entry(weight: float, score: Optional[float]) -> dict:
            if score is None:
                return {"score": None, "weight": weight, "weighted": 0, "analyzed": False}
            return {
                "score": round(score, 1),
                "weight": weight,
                "weighted": round(weight * score, 1),
                "analyzed": True,
            }

        breakdown = {
            "url": _entry(self.weight_url, url_score),
            "content": _entry(self.weight_content, content_score),
            "headers": _entry(self.weight_headers, header_score),
            "network": _entry(self.weight_network, network_score),
            "threat_intel_boost": round(intel_boost, 1),
        }

        return RiskScore(
            total=round(total, 1),
            url_score=round(url_score or 0, 1),
            content_score=round(content_score or 0, 1),
            header_score=round(header_score or 0, 1),
            network_score=round(network_score or 0, 1),
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
