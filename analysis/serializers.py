"""
Сериализаторы для REST API.
"""
from rest_framework import serializers
from .models import (
    AnalysisSession,
    LogEntry,
    DetectedAnomaly,
    Alert,
    AnomalyType,
    WebServer,
)


class LogEntryMinSerializer(serializers.ModelSerializer):
    """Краткое представление записи лога (вложенное в аномалию)."""

    class Meta:
        model = LogEntry
        fields = [
            "id",
            "timestamp",
            "client_ip",
            "method",
            "uri",
            "status_code",
            "user_agent",
        ]


class LogEntrySerializer(serializers.ModelSerializer):
    """Полное представление записи лога (опционально с features)."""

    class Meta:
        model = LogEntry
        fields = [
            "id",
            "timestamp",
            "client_ip",
            "method",
            "uri",
            "status_code",
            "user_agent",
            "raw_line",
            "features",
            "analysis_session_id",
        ]
        read_only_fields = fields


class AnomalyTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnomalyType
        fields = ("id", "code", "name", "severity")


class DetectedAnomalySerializer(serializers.ModelSerializer):
    """Сериализатор аномалии с обязательным полем explanation."""

    log_entry = LogEntryMinSerializer(read_only=True)
    anomaly_type_code = serializers.CharField(
        source="anomaly_type.code", read_only=True, allow_null=True
    )
    anomaly_type_name = serializers.CharField(
        source="anomaly_type.name", read_only=True, allow_null=True
    )
    anomaly_type_severity = serializers.IntegerField(
        source="anomaly_type.severity", read_only=True, allow_null=True
    )

    class Meta:
        model = DetectedAnomaly
        fields = [
            "id",
            "detected_at",
            "detection_method",
            "confidence_score",
            "risk_level",
            "model_score",
            "explanation",
            "is_false_positive",
            "anomaly_type",
            "anomaly_type_code",
            "anomaly_type_name",
            "anomaly_type_severity",
            "log_entry",
            "analysis_session_id",
        ]
        read_only_fields = fields


class AlertSerializer(serializers.ModelSerializer):
    """Список алертов с вложенной аномалией."""

    anomaly = DetectedAnomalySerializer(read_only=True)

    class Meta:
        model = Alert
        fields = ("id", "created_at", "status", "risk_level", "message", "anomaly")


class AnalysisSessionSerializer(serializers.ModelSerializer):
    """Сессия анализа (результат загрузки и т.д.)."""

    class Meta:
        model = AnalysisSession
        fields = (
            "id",
            "start_time",
            "end_time",
            "model_version",
            "logs_processed_count",
            "anomalies_count",
        )


class LogUploadSerializer(serializers.Serializer):
    """Валидация загружаемого файла логов."""

    file = serializers.FileField(help_text="Файл access.log (Nginx/Apache combined)")
    web_server_id = serializers.PrimaryKeyRelatedField(
        queryset=WebServer.objects.all(),
        required=False,
        allow_null=True,
        help_text="Опционально: привязать записи к веб-серверу",
    )

    def validate_file(self, value):
        max_size_mb = 20
        if value.size > max_size_mb * 1024 * 1024:
            raise serializers.ValidationError(
                f"Максимальный размер файла: {max_size_mb} MB."
            )
        name = getattr(value, "name", "") or ""
        if not (name.endswith(".log") or name.endswith(".txt") or ".log" in name):
            raise serializers.ValidationError(
                "Разрешены файлы с расширением .log или .txt."
            )
        return value
