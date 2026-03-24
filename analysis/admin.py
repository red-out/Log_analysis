"""
Регистрация моделей в Django Admin для управления логами, аномалиями и алертами.
"""
from django.contrib import admin
from .models import (
    WebServer,
    AnalysisSession,
    LogEntry,
    AnomalyType,
    DetectedAnomaly,
    Alert,
    Report,
)


@admin.register(WebServer)
class WebServerAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at")
    search_fields = ("name",)


@admin.register(AnalysisSession)
class AnalysisSessionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "start_time",
        "end_time",
        "model_version",
        "logs_processed_count",
        "anomalies_count",
        "created_by",
    )
    list_filter = ("start_time",)
    readonly_fields = ("start_time", "logs_processed_count", "anomalies_count")
    date_hierarchy = "start_time"


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ("id", "timestamp", "client_ip", "method", "uri_short", "status_code")
    list_filter = ("method", "status_code", "timestamp")
    search_fields = ("client_ip", "uri", "user_agent")
    readonly_fields = ("raw_line", "features")
    date_hierarchy = "timestamp"

    def uri_short(self, obj: LogEntry) -> str:
        return (obj.uri[:60] + "…") if len(obj.uri) > 60 else obj.uri

    uri_short.short_description = "URI"


@admin.register(AnomalyType)
class AnomalyTypeAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "severity")
    list_filter = ("severity",)


@admin.register(DetectedAnomaly)
class DetectedAnomalyAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "log_entry",
        "detection_method",
        "risk_level",
        "confidence_score",
        "is_false_positive",
        "detected_at",
    )
    list_filter = ("detection_method", "risk_level", "is_false_positive", "detected_at")
    search_fields = ("explanation", "log_entry__uri")
    readonly_fields = ("detected_at", "model_score", "explanation")
    date_hierarchy = "detected_at"


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("id", "anomaly", "risk_level", "status", "created_at", "recipient")
    list_filter = ("risk_level", "status", "created_at")
    readonly_fields = ("created_at",)


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("id", "generated_at", "generated_by")
    readonly_fields = ("generated_at", "summary")
