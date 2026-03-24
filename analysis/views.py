"""
REST API: загрузка логов, список аномалий, алертов, сессий, статистика.
"""
from __future__ import annotations

import io
import logging
import time
from typing import Any, Dict

from django.db import DatabaseError
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import UserRateThrottle
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

from .models import Alert, AnalysisSession, DetectedAnomaly, LogEntry, AnomalyType, WebServer
from .serializers import (
    DetectedAnomalySerializer,
    AlertSerializer,
    AnalysisSessionSerializer,
    LogEntrySerializer,
    LogUploadSerializer,
)
from .services.parser import NginxAccessLogParser
from .services.ml_engine import IsolationForestEngine
from .services.risk import calculate_risk_level

logger = logging.getLogger(__name__)


class LogUploadThrottle(UserRateThrottle):
    """Ограничение частоты загрузки логов (защита от массового заполнения)."""
    rate = "10/min"
    scope = "log_upload"


def with_db_retry(callable_fn, retries: int = 3, base_delay_sec: float = 0.5):
    """
    Выполнить DB-операцию с коротким exponential backoff.
    """
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


class LogUploadView(APIView):
    """
    POST /api/logs/upload/
    Загрузка файла access.log, парсинг, извлечение признаков, запуск ML и сигнатур.
    Доступно только администраторам.
    """

    permission_classes = [IsAdminUser]
    # Поддерживаем как multipart/form-data (file), так и бинарное тело (application/octet-stream)
    parser_classes = [MultiPartParser]
    throttle_classes = [LogUploadThrottle]

    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        Поддерживаются два режима:

        1) multipart/form-data с полем file (как раньше, Swagger/Postman form-data)
        2) бинарное тело запроса (application/octet-stream или text/plain),
           когда весь лог-файл отправляется как raw body (Postman → Body → binary).
        """
        ml_engine = IsolationForestEngine()
        parser = NginxAccessLogParser()

        content: bytes
        web_server: WebServer | None = None

        # Режим 1: multipart/form-data (старое поведение)
        content_type = request.content_type or ""
        if content_type.startswith("multipart/"):
            serializer = LogUploadSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            file_obj = serializer.validated_data["file"]
            web_server = serializer.validated_data.get("web_server_id")
            try:
                content = file_obj.read()
            except Exception as e:
                logger.exception("Failed to read upload: %s", e)
                return Response(
                    {"detail": "Ошибка чтения файла."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            # Режим 2: бинарное тело (raw). Например, Postman → Body → binary.
            content = request.body or b""
            if not content:
                return Response(
                    {"detail": "Пустое тело запроса."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # web_server_id можно передать как query-параметр, напр. ?web_server_id=1
            web_server_id = request.query_params.get("web_server_id")
            if web_server_id:
                try:
                    web_server = WebServer.objects.get(pk=web_server_id)
                except (WebServer.DoesNotExist, ValueError):
                    return Response(
                        {"detail": "Некорректный web_server_id."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        try:
            session = with_db_retry(
                lambda: AnalysisSession.objects.create(
                    model_version="isolation_forest_v1",
                    created_by=request.user,
                )
            )
        except DatabaseError:
            return Response(
                {"detail": "База данных временно недоступна. Попробуйте повторить загрузку позже."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        created_logs = 0
        created_anomalies = 0
        anomaly_threshold = 0.65  # порог уверенности для создания DetectedAnomaly

        try:
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            text = content.decode("cp1251", errors="ignore")

        lines = text.splitlines()
        for line in lines:
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
                created_logs += 1
            except DatabaseError as e:
                logger.warning("Database temporary error on LogEntry create: %s", e)
                continue
            except Exception as e:
                logger.warning("LogEntry create failed: %s", e)
                continue

            features: Dict[str, Any] = log_entry.features or {}
            prediction = ml_engine.predict(features)

            # Сигнатурные срабатывания (на основе признаков)
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
            if is_anomaly_ml or has_signature:
                if is_anomaly_ml and has_signature:
                    detection_method = DetectedAnomaly.DetectionMethod.HYBRID
                elif has_signature:
                    detection_method = DetectedAnomaly.DetectionMethod.SIGNATURE
                else:
                    detection_method = DetectedAnomaly.DetectionMethod.ML

                anomaly_type = None
                # Приоритет: SQLI, XSS, PATH_TRAVERSAL, SENSITIVE_FILE_SCAN, INVALID_METHOD
                if has_sqli:
                    anomaly_type = AnomalyType.objects.filter(code="SQLI").first()
                elif has_xss:
                    anomaly_type = AnomalyType.objects.filter(code="XSS").first()
                elif has_path_traversal:
                    anomaly_type = AnomalyType.objects.filter(code="PATH_TRAVERSAL").first()
                elif has_sensitive_file_scan:
                    anomaly_type = AnomalyType.objects.filter(code="SENSITIVE_FILE_SCAN").first()
                elif has_invalid_method:
                    anomaly_type = AnomalyType.objects.filter(code="INVALID_METHOD").first()

                if not anomaly_type and is_anomaly_ml:
                    anomaly_type = AnomalyType.objects.filter(code="STAT_ANOMALY").first()

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
                except DatabaseError as e:
                    logger.warning("Database temporary error on anomaly create: %s", e)
                    continue

                created_anomalies += 1

                if risk_level in {"high", "critical"}:
                    try:
                        with_db_retry(
                            lambda: Alert.objects.create(
                                anomaly=anomaly,
                                recipient=request.user,
                                risk_level=risk_level,
                                message=f"Обнаружена аномалия #{anomaly.id}: {prediction.explanation[:200]}",
                            )
                        )
                    except DatabaseError as e:
                        logger.warning("Database temporary error on alert create: %s", e)
                        continue

        session.logs_processed_count = created_logs
        session.anomalies_count = created_anomalies
        session.end_time = timezone.now()
        try:
            with_db_retry(
                lambda: session.save(update_fields=["logs_processed_count", "anomalies_count", "end_time"])
            )
        except DatabaseError:
            return Response(
                {
                    "detail": (
                        "Логи обработаны, но база данных временно недоступна для финализации сессии. "
                        "Проверьте подключение к PostgreSQL и повторите запрос позже."
                    )
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(
            {
                "session_id": session.id,
                "logs_processed": created_logs,
                "anomalies_detected": created_anomalies,
            },
            status=status.HTTP_201_CREATED,
        )


class DetectedAnomalyViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Список и детали обнаруженных аномалий.
    GET /api/anomalies/
    GET /api/anomalies/{id}/
    Фильтры: detection_method, anomaly_type__code, log_entry__client_ip и др.
    """

    queryset = DetectedAnomaly.objects.select_related(
        "log_entry", "anomaly_type", "analysis_session"
    )
    serializer_class = DetectedAnomalySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = [
        "detection_method",
        "risk_level",
        "anomaly_type__code",
        "is_false_positive",
        "log_entry__client_ip",
        "log_entry__status_code",
    ]
    ordering_fields = ["detected_at", "confidence_score", "id"]
    ordering = ["-detected_at"]
    search_fields = ["explanation", "log_entry__uri", "log_entry__user_agent"]


class AlertViewSet(viewsets.ModelViewSet):
    """
    Алерты: список, детали, смена статуса (PATCH).
    GET /api/alerts/
    """
    queryset = Alert.objects.select_related("anomaly", "anomaly__log_entry")
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["status", "risk_level"]
    ordering = ["-created_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        if not self.request.user.is_staff:
            return qs.filter(recipient=self.request.user)
        return qs


class AnalysisSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Сессии анализа (история запусков).
    GET /api/sessions/
    """
    queryset = AnalysisSession.objects.all().order_by("-start_time")
    serializer_class = AnalysisSessionSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.OrderingFilter]
    ordering_fields = ["start_time", "logs_processed_count"]


class LogEntryViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Записи логов (только чтение).
    GET /api/log-entries/
    """
    queryset = LogEntry.objects.all().order_by("-timestamp")
    serializer_class = LogEntrySerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ["client_ip", "method", "status_code", "analysis_session"]
    ordering_fields = ["timestamp", "id"]
    search_fields = ["uri", "user_agent", "client_ip"]


class StatsView(APIView):
    """
    GET /api/stats/
    Сводная статистика: количество логов, аномалий, алертов по типам.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        from django.db.models import Count
        total_logs = LogEntry.objects.count()
        total_anomalies = DetectedAnomaly.objects.count()
        total_alerts = Alert.objects.filter(status="new").count()
        by_method = dict(
            DetectedAnomaly.objects.values("detection_method").annotate(c=Count("id")).values_list("detection_method", "c")
        )
        by_type = dict(
            DetectedAnomaly.objects.filter(anomaly_type__isnull=False)
            .values("anomaly_type__code")
            .annotate(c=Count("id"))
            .values_list("anomaly_type__code", "c")
        )
        return Response({
            "total_log_entries": total_logs,
            "total_anomalies": total_anomalies,
            "new_alerts_count": total_alerts,
            "anomalies_by_method": by_method,
            "anomalies_by_type": by_type,
        })
