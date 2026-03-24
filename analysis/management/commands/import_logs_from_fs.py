"""
Импорт логов из файловой системы с запуском анализа.

Пример:
python manage.py import_logs_from_fs --path /var/log/nginx --recursive --created-by admin
"""
from __future__ import annotations

import time
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError
from django.utils import timezone

from analysis.models import Alert, AnalysisSession, AnomalyType, DetectedAnomaly, WebServer
from analysis.services.ml_engine import IsolationForestEngine
from analysis.services.parser import NginxAccessLogParser
from analysis.services.risk import calculate_risk_level

User = get_user_model()


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


class Command(BaseCommand):
    help = "Импортировать .log/.txt файлы из файловой системы, распарсить и выполнить анализ."

    def add_arguments(self, parser):
        parser.add_argument("--path", required=True, help="Путь к файлу логов или директории.")
        parser.add_argument("--recursive", action="store_true", help="Рекурсивный поиск .log/.txt в директории.")
        parser.add_argument("--web-server-id", type=int, default=None, help="Опционально: ID WebServer.")
        parser.add_argument("--created-by", type=str, default=None, help="Username пользователя-создателя сессии.")
        parser.add_argument("--skip-analysis", action="store_true", help="Только загрузка логов без детекции аномалий.")

    def handle(self, *args, **options):
        source_path = Path(options["path"])
        if not source_path.exists():
            raise CommandError(f"Путь не существует: {source_path}")

        created_by = None
        if options["created_by"]:
            created_by = User.objects.filter(username=options["created_by"]).first()
            if created_by is None:
                raise CommandError(f"Пользователь не найден: {options['created_by']}")

        web_server = None
        if options["web_server_id"] is not None:
            web_server = WebServer.objects.filter(pk=options["web_server_id"]).first()
            if web_server is None:
                raise CommandError(f"WebServer с id={options['web_server_id']} не найден.")

        file_paths = self._collect_files(source_path, recursive=options["recursive"])
        if not file_paths:
            raise CommandError("Не найдено подходящих файлов (.log/.txt).")

        parser = NginxAccessLogParser()
        ml_engine = IsolationForestEngine()
        anomaly_threshold = 0.65
        skip_analysis = bool(options["skip_analysis"])

        try:
            session = with_db_retry(
                lambda: AnalysisSession.objects.create(
                    model_version="isolation_forest_v1",
                    created_by=created_by,
                )
            )
        except DatabaseError as e:
            raise CommandError(f"База данных недоступна: {e}") from e

        created_logs = 0
        created_anomalies = 0

        for file_path in file_paths:
            self.stdout.write(f"Обработка файла: {file_path}")
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                text = file_path.read_text(encoding="cp1251", errors="ignore")

            for line in text.splitlines():
                parsed = parser.parse_line(line)
                if parsed is None:
                    continue

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
                    [has_sqli, has_xss, has_path_traversal, has_sensitive_file_scan, has_invalid_method]
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

                anomaly_type = self._resolve_anomaly_type(
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
                    created_anomalies += 1
                except DatabaseError:
                    continue

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
        with_db_retry(lambda: session.save(update_fields=["logs_processed_count", "anomalies_count", "end_time"]))

        self.stdout.write(
            self.style.SUCCESS(
                f"Готово. session_id={session.id}, logs_processed={created_logs}, anomalies_detected={created_anomalies}"
            )
        )

    def _collect_files(self, path: Path, recursive: bool) -> list[Path]:
        if path.is_file():
            if path.suffix.lower() in {".log", ".txt"}:
                return [path]
            return []
        if recursive:
            return sorted([p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".log", ".txt"}])
        return sorted([p for p in path.iterdir() if p.is_file() and p.suffix.lower() in {".log", ".txt"}])

    def _resolve_anomaly_type(
        self,
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
