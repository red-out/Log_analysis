"""
Единая логика загрузки/парсинга/анализа логов.

Используется из:
- REST API upload
- CLI import_logs_from_fs
- UI (web pages)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional

from django.db import DatabaseError
from django.utils import timezone

from analysis.models import Alert, AnalysisSession, AnomalyType, DetectedAnomaly, WebServer
from analysis.services.ml_engine import IsolationForestEngine
from analysis.services.parser import NginxAccessLogParser, ParsedLogLine
from analysis.services.risk import calculate_risk_level

logger = logging.getLogger(__name__)

# Приоритет классификации: от более критичных OWASP-классов к мягким сигналам.
_ATTACK_TYPE_CODES = (
    "SQLI",
    "XSS",
    "XXE",
    "CMD_INJECTION",
    "PATH_TRAVERSAL",
    "LDAP_INJECTION",
    "SSRF",
    "SENSITIVE_FILE_SCAN",
    "OPEN_REDIRECT",
    "INVALID_METHOD",
)
_SOFT_TYPE_CODES = (
    "LONG_URI_PROBE",
    "UNUSUAL_UA",
)
_FEATURE_TO_ATTACK_CODE = {
    "has_sqli_signature": "SQLI",
    "has_xss_signature": "XSS",
    "has_xxe_signature": "XXE",
    "has_cmd_injection_signature": "CMD_INJECTION",
    "has_path_traversal_signature": "PATH_TRAVERSAL",
    "has_ldap_injection_signature": "LDAP_INJECTION",
    "has_ssrf_signature": "SSRF",
    "has_sensitive_file_scan_signature": "SENSITIVE_FILE_SCAN",
    "has_open_redirect_signature": "OPEN_REDIRECT",
    "has_invalid_method": "INVALID_METHOD",
}
_FEATURE_TO_SOFT_CODE = {
    "has_long_uri_probe": "LONG_URI_PROBE",
    "has_unusual_ua": "UNUSUAL_UA",
}
_CODE_TO_ATTACK_FEATURE = {v: k for k, v in _FEATURE_TO_ATTACK_CODE.items()}
_CODE_TO_SOFT_FEATURE = {v: k for k, v in _FEATURE_TO_SOFT_CODE.items()}
ML_UNCLASSIFIED_CODE = "ML_UNCLASSIFIED"


def with_db_retry(callable_fn, retries: int = 3, base_delay_sec: float = 0.5):
    last_error = None
    for attempt in range(retries):
        try:
            return callable_fn()
        except DatabaseError as e:
            last_error = e
            if attempt == retries - 1:
                break
            time.sleep(base_delay_sec * (2 ** attempt))
    raise last_error


@dataclass(frozen=True)
class IngestResult:
    """
    Результат одного прогона ingest.

    lines_skipped — строки без сохранённого LogEntry: нераспознанный combined
    (непустые, не комментарии) или ошибка сохранения в БД.
    """

    session_id: int
    logs_processed: int
    anomalies_detected: int
    lines_skipped: int = 0


def ingest_parsed_lines(
    *,
    parsed_lines: Iterable[ParsedLogLine],
    created_by,
    web_server: Optional[WebServer] = None,
    skip_analysis: bool = False,
    model_version: str = "isolation_forest_v1",
    anomaly_threshold: float = 0.65,
) -> IngestResult:
    """
    Принять поток распарсенных строк и выполнить сохранение + (опционально) анализ.
    """
    parser = NginxAccessLogParser()
    ml_engine = IsolationForestEngine()

    session = with_db_retry(
        lambda: AnalysisSession.objects.create(
            model_version=model_version,
            created_by=created_by,
        )
    )

    created_logs = 0
    created_anomalies = 0
    lines_skipped = 0
    skipped_anomaly_writes = 0
    skipped_alert_writes = 0
    ip_counts: dict[str, int] = {}

    for parsed in parsed_lines:
        try:
            log_entry = with_db_retry(
                lambda p=parsed, counts=ip_counts: parser.create_log_entry(
                    p,
                    web_server=web_server,
                    analysis_session=session,
                    ip_counts=counts,
                )
            )
        except DatabaseError as e:
            lines_skipped += 1
            logger.warning(
                "ingest: не удалось сохранить LogEntry (session_id=%s, ip=%s, uri=%r): %s",
                session.id,
                parsed.client_ip,
                (parsed.uri or "")[:200],
                e,
            )
            continue
        except Exception as e:
            lines_skipped += 1
            logger.warning(
                "ingest: ошибка при сохранении LogEntry (session_id=%s, ip=%s, uri=%r): %s",
                session.id,
                parsed.client_ip,
                (parsed.uri or "")[:200],
                e,
                exc_info=True,
            )
            continue

        created_logs += 1
        if skip_analysis:
            continue

        features = log_entry.features or {}
        prediction = ml_engine.predict(features)

        has_attack_signature = bool(int(features.get("has_attack_signature", 0)))
        has_soft_signal = bool(int(features.get("has_soft_signal", 0)))
        has_rule_signal = has_attack_signature or has_soft_signal

        is_anomaly_ml = prediction.is_anomaly and prediction.confidence_score >= anomaly_threshold
        if not (is_anomaly_ml or has_rule_signal):
            continue

        if is_anomaly_ml and has_rule_signal:
            detection_method = DetectedAnomaly.DetectionMethod.HYBRID
        elif has_rule_signal:
            detection_method = DetectedAnomaly.DetectionMethod.SIGNATURE
        else:
            detection_method = DetectedAnomaly.DetectionMethod.ML

        anomaly_type = _resolve_anomaly_type(features, is_anomaly_ml=is_anomaly_ml)
        type_code = getattr(anomaly_type, "code", None) if anomaly_type else None

        risk_level = calculate_risk_level(severity=getattr(anomaly_type, "severity", None))

        explanation = prediction.explanation
        if detection_method == DetectedAnomaly.DetectionMethod.ML:
            explanation = (
                f"{explanation} "
                "Класс атаки не определён сигнатурами (сценарий zero-day / неизвестный паттерн). "
                "Рекомендуется ручная проверка аналитиком."
            )

        try:
            anomaly = with_db_retry(
                lambda le=log_entry, at=anomaly_type, dm=detection_method, pred=prediction, rl=risk_level, expl=explanation: DetectedAnomaly.objects.create(
                    log_entry=le,
                    analysis_session=session,
                    anomaly_type=at,
                    detection_method=dm,
                    confidence_score=pred.confidence_score,
                    model_score=pred.raw_score,
                    explanation=expl,
                    risk_level=rl,
                )
            )
        except DatabaseError as e:
            skipped_anomaly_writes += 1
            logger.warning(
                "ingest: не удалось сохранить DetectedAnomaly (session_id=%s, log_entry_id=%s): %s",
                session.id,
                log_entry.id,
                e,
            )
            continue

        created_anomalies += 1

        if _should_create_alert(risk_level, detection_method, type_code):
            if detection_method == DetectedAnomaly.DetectionMethod.ML:
                alert_msg = (
                    f"[Проверка] Возможная неизвестная угроза (только ML) #{anomaly.id}: "
                    f"{explanation[:200]}"
                )
            else:
                alert_msg = f"Обнаружена аномалия #{anomaly.id}: {explanation[:200]}"
            try:
                with_db_retry(
                    lambda an=anomaly, rl=risk_level, msg=alert_msg: Alert.objects.create(
                        anomaly=an,
                        recipient=created_by,
                        risk_level=rl,
                        message=msg,
                    )
                )
            except DatabaseError as e:
                skipped_alert_writes += 1
                logger.warning(
                    "ingest: не удалось сохранить Alert (session_id=%s, anomaly_id=%s): %s",
                    session.id,
                    anomaly.id,
                    e,
                )

    if lines_skipped:
        logger.warning(
            "ingest: сессия %s завершена с lines_skipped=%s (ошибки сохранения LogEntry).",
            session.id,
            lines_skipped,
        )
    if skipped_anomaly_writes or skipped_alert_writes:
        logger.warning(
            "ingest: сессия %s — пропуски при записи аномалий/алертов: anomalies=%s, alerts=%s",
            session.id,
            skipped_anomaly_writes,
            skipped_alert_writes,
        )

    session.logs_processed_count = created_logs
    session.anomalies_count = created_anomalies
    session.end_time = timezone.now()
    with_db_retry(
        lambda: session.save(update_fields=["logs_processed_count", "anomalies_count", "end_time"])
    )

    return IngestResult(
        session_id=session.id,
        logs_processed=created_logs,
        anomalies_detected=created_anomalies,
        lines_skipped=lines_skipped,
    )


def ingest_text(
    *,
    text: str,
    created_by,
    web_server: Optional[WebServer] = None,
    skip_analysis: bool = False,
) -> IngestResult:
    """
    Принять текст лог-файла, распарсить и выполнить ingest.
    """
    p = NginxAccessLogParser()
    parsed_lines: List[ParsedLogLine] = []
    skipped_parse = 0
    parse_samples: List[str] = []

    for line in text.splitlines():
        pl = p.parse_line(line)
        if pl is not None:
            parsed_lines.append(pl)
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        skipped_parse += 1
        if len(parse_samples) < 5:
            parse_samples.append(stripped[:200])

    if skipped_parse:
        logger.warning(
            "ingest: пропущено %s строк с нераспознанным форматом combined (первые фрагменты): %s",
            skipped_parse,
            parse_samples,
        )

    result = ingest_parsed_lines(
        parsed_lines=parsed_lines,
        created_by=created_by,
        web_server=web_server,
        skip_analysis=skip_analysis,
    )
    return IngestResult(
        session_id=result.session_id,
        logs_processed=result.logs_processed,
        anomalies_detected=result.anomalies_detected,
        lines_skipped=skipped_parse + result.lines_skipped,
    )


def _type_by_code(code: str):
    return AnomalyType.objects.filter(code=code).first()


def _resolve_anomaly_type(features: dict, *, is_anomaly_ml: bool):
    for code in _ATTACK_TYPE_CODES:
        feat = _CODE_TO_ATTACK_FEATURE.get(code)
        if feat and int(features.get(feat, 0)):
            return _type_by_code(code)
    for code in _SOFT_TYPE_CODES:
        feat = _CODE_TO_SOFT_FEATURE.get(code)
        if feat and int(features.get(feat, 0)):
            return _type_by_code(code)
    if is_anomaly_ml:
        return _type_by_code(ML_UNCLASSIFIED_CODE) or _type_by_code("STAT_ANOMALY")
    return None


def _should_create_alert(risk_level: str, detection_method: str, type_code: str | None) -> bool:
    if risk_level in {"high", "critical"}:
        return True
    if (
        detection_method == DetectedAnomaly.DetectionMethod.ML
        and type_code == ML_UNCLASSIFIED_CODE
        and risk_level == "medium"
    ):
        return True
    return False

