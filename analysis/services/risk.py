"""
Нормализация оценки риска для аномалий и алертов.
"""
from __future__ import annotations


def calculate_risk_level(confidence_score: float, severity: int | None) -> str:
    """
    Вернуть нормализованный уровень риска: low/medium/high/critical.
    """
    sev = int(severity or 0)
    conf = float(confidence_score or 0.0)

    if sev >= 5 or conf >= 0.9:
        return "critical"
    if sev >= 4 or conf >= 0.8:
        return "high"
    if sev >= 3 or conf >= 0.65:
        return "medium"
    return "low"
