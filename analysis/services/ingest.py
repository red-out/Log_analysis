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

    for parsed in parsed_lines:
        try:
            log_entry = with_db_retry(
                lambda p=parsed: parser.create_log_entry(
                    p,
                    web_server=web_server,
                    analysis_session=session,
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

        has_sqli = bool(int(features.get("has_sqli_signature", 0)))
        has_xss = bool(int(features.get("has_xss_signature", 0)))
        has_path_traversal = bool(int(features.get("has_path_traversal_signature", 0)))
        has_sensitive_file_scan = bool(int(features.get("has_sensitive_file_scan_signature", 0)))
        has_invalid_method = bool(int(features.get("has_invalid_method", 0)))
        has_signature = any(
            [
                has_sqli,
                has_xss,
                has_path_traversal,
                has_sensitive_file_scan,
                has_invalid_method,
            ]
        )

        is_anomaly_ml = prediction.is_anomaly and prediction.confidence_score >= anomaly_threshold
        if not (is_anomaly_ml or has_signature):
            continue

        if is_anomaly_ml and has_signature:
            detection_method = DetectedAnomaly.DetectionMethod.HYBRID
        elif has_signature:
            detection_method = DetectedAnomaly.DetectionMethod.SIGNATURE
        else:
            detection_method = DetectedAnomaly.DetectionMethod.ML

        anomaly_type = _resolve_anomaly_type(
            has_sqli=has_sqli,
            has_xss=has_xss,
            has_path_traversal=has_path_traversal,
            has_sensitive_file_scan=has_sensitive_file_scan,
            has_invalid_method=has_invalid_method,
            is_anomaly_ml=is_anomaly_ml,
        )

        risk_level = calculate_risk_level(
            confidence_score=prediction.confidence_score,
            severity=getattr(anomaly_type, "severity", None),
        )

        try:
            anomaly = with_db_retry(
                lambda le=log_entry, at=anomaly_type, dm=detection_method, pred=prediction, rl=risk_level: DetectedAnomaly.objects.create(
                    log_entry=le,
                    analysis_session=session,
                    anomaly_type=at,
                    detection_method=dm,
                    confidence_score=pred.confidence_score,
                    model_score=pred.raw_score,
                    explanation=pred.explanation,
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

        if risk_level in {"high", "critical"}:
            try:
                with_db_retry(
                    lambda an=anomaly, rl=risk_level, expl=prediction.explanation: Alert.objects.create(
                        anomaly=an,
                        recipient=created_by,
                        risk_level=rl,
                        message=f"Обнаружена аномалия #{an.id}: {expl[:200]}",
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


def _resolve_anomaly_type(
    *,
    has_sqli: bool,
    has_xss: bool,
    has_path_traversal: bool,
    has_sensitive_file_scan: bool,
    has_invalid_method: bool,
    is_anomaly_ml: bool,
):
    if has_sqli:
        return AnomalyType.objects.filter(code="SQLI").first()
    if has_xss:
        return AnomalyType.objects.filter(code="XSS").first()
    if has_path_traversal:
        return AnomalyType.objects.filter(code="PATH_TRAVERSAL").first()
    if has_sensitive_file_scan:
        return AnomalyType.objects.filter(code="SENSITIVE_FILE_SCAN").first()
    if has_invalid_method:
        return AnomalyType.objects.filter(code="INVALID_METHOD").first()
    if is_anomaly_ml:
        return AnomalyType.objects.filter(code="STAT_ANOMALY").first()
    return None

