"""
REST API: загрузка логов, список аномалий, алертов, сессий.
"""
from __future__ import annotations

import logging
from typing import Any

from django.db import DatabaseError
from rest_framework import status, viewsets
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import UserRateThrottle
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

from .models import Alert, AnalysisSession, DetectedAnomaly, LogEntry, WebServer
from .serializers import (
    DetectedAnomalySerializer,
    AlertSerializer,
    AnalysisSessionSerializer,
    LogEntrySerializer,
    LogUploadSerializer,
)
from .services.parser import NginxAccessLogParser
from .services.ingest import ingest_text, with_db_retry

logger = logging.getLogger(__name__)


class LogUploadThrottle(UserRateThrottle):
    """Ограничение частоты загрузки логов (защита от массового заполнения)."""
    rate = "10/min"
    scope = "log_upload"

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
            text = content.decode("utf-8", errors="ignore")
        except Exception:
            text = content.decode("cp1251", errors="ignore")

        try:
            result = ingest_text(text=text, created_by=request.user, web_server=web_server)
        except DatabaseError:
            return Response(
                {"detail": "База данных временно недоступна. Попробуйте повторить загрузку позже."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        return Response(
            {
                "session_id": result.session_id,
                "logs_processed": result.logs_processed,
                "anomalies_detected": result.anomalies_detected,
                "lines_skipped": result.lines_skipped,
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


