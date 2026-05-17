"""
Нормализация уровня риска по severity типа аномалии (шкала 1–5, OWASP-ориентированная).

Уверенность ML (confidence_score) на risk_level не влияет — она хранится отдельно
в DetectedAnomaly и используется для порога детекции и объяснений.
"""
from __future__ import annotations


def calculate_risk_level(*, severity: int | None) -> str:
    """
    Вернуть low / medium / high / critical только из severity типа уязвимости.

    5 → critical (напр. SQLi, XSS, RCE)
    4 → high     (напр. SSRF, LDAPi, скан чувствительных путей)
    3 → medium   (напр. open redirect, нетипичный метод, ML без класса атаки)
    1–2 → low    (информационные / поведенческие сигналы)
    """
    sev = int(severity or 0)
    if sev >= 5:
        return "critical"
    if sev == 4:
        return "high"
    if sev == 3:
        return "medium"
    return "low"
