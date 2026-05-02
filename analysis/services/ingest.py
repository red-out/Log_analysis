"""
Единая логика загрузки/парсинга/анализа логов.

Используется из:
- REST API upload
- CLI import_logs_from_fs
- UI (web pages)
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional

from django.db import DatabaseError
from django.utils import timezone

from analysis.models import Alert, AnalysisSession, AnomalyType, DetectedAnomaly, WebServer
from analysis.services.ml_engine import IsolationForestEngine
from analysis.services.parser import NginxAccessLogParser, ParsedLogLine
from analysis.services.risk import calculate_risk_level


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
    session_id: int
    logs_processed: int
    anomalies_detected: int


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

    for parsed in parsed_lines:
        try:
            log_entry = with_db_retry(
                lambda: parser.create_log_entry(
                    parsed,
                    web_server=web_server,
                    analysis_session=session,
                )
            )
        except DatabaseError:
            continue
        except Exception:
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
                lambda: DetectedAnomaly.objects.create(
                    log_entry=log_entry,
                    analysis_session=session,
                    anomaly_type=anomaly_type,
                    detection_method=detection_method,
                    confidence_score=prediction.confidence_score,
                    model_score=prediction.raw_score,
                    explanation=prediction.explanation,
                    risk_level=risk_level,
                )
            )
        except DatabaseError:
            continue

        created_anomalies += 1

        if risk_level in {"high", "critical"}:
            try:
                with_db_retry(
                    lambda: Alert.objects.create(
                        anomaly=anomaly,
                        recipient=created_by,
                        risk_level=risk_level,
                        message=f"Обнаружена аномалия #{anomaly.id}: {prediction.explanation[:200]}",
                    )
                )
            except DatabaseError:
                continue

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
    parsed_iter = (pl for pl in (p.parse_line(line) for line in text.splitlines()) if pl is not None)
    return ingest_parsed_lines(
        parsed_lines=parsed_iter,
        created_by=created_by,
        web_server=web_server,
        skip_analysis=skip_analysis,
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

