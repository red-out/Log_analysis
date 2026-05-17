"""
Модели для хранения логов, аномалий, алертов и сессий анализа.
Схема БД с индексами для быстрого поиска по timestamp и client_ip.
"""
from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

User = get_user_model()


class WebServer(models.Model):
    """Источник логов (веб-сервер)."""

    name = models.CharField("Название", max_length=150, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Веб-сервер"
        verbose_name_plural = "Веб-серверы"

    def __str__(self) -> str:
        return self.name


class AnalysisSession(models.Model):
    """
    Одна сессия анализа (обработка одного или нескольких лог-файлов).
    """

    start_time = models.DateTimeField("Начало", default=timezone.now)
    end_time = models.DateTimeField("Конец", null=True, blank=True)
    model_version = models.CharField("Версия модели", max_length=64, blank=True)
    logs_processed_count = models.PositiveIntegerField("Обработано записей", default=0)
    anomalies_count = models.PositiveIntegerField("Найдено аномалий", default=0)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="analysis_sessions",
    )

    class Meta:
        verbose_name = "Сессия анализа"
        verbose_name_plural = "Сессии анализа"
        ordering = ["-start_time"]

    def __str__(self) -> str:
        return f"Сессия #{self.id} ({self.start_time:%Y-%m-%d %H:%M})"


class LogEntry(models.Model):
    """
    Одна распарсенная запись access.log (нормализованная).
    """

    web_server = models.ForeignKey(
        WebServer,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="log_entries",
        verbose_name="Веб-сервер",
    )
    analysis_session = models.ForeignKey(
        AnalysisSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="log_entries",
        verbose_name="Сессия анализа",
    )

    timestamp = models.DateTimeField("Время", db_index=True)
    client_ip = models.GenericIPAddressField("IP клиента", db_index=True)
    method = models.CharField("Метод", max_length=10)
    uri = models.TextField("URI")
    status_code = models.PositiveIntegerField("Код ответа")
    user_agent = models.TextField("User-Agent", blank=True)
    raw_line = models.TextField("Исходная строка")

    features = models.JSONField(
        "Признаки для ML",
        default=dict,
        blank=True,
        help_text="Извлечённые числовые/категориальные признаки.",
    )

    class Meta:
        verbose_name = "Запись лога"
        verbose_name_plural = "Записи логов"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["timestamp", "client_ip"]),
            models.Index(fields=["-timestamp"]),
        ]

    def __str__(self) -> str:
        return f"{self.client_ip} {self.method} {self.uri[:50]}"


class AnomalyType(models.Model):
    """
    Справочник типов аномалий: SQLi, XSS, статистическая аномалия и т.д.
    """

    code = models.CharField(
        "Код",
        max_length=32,
        unique=True,
        help_text="Напр. SQLI, XSS, STAT_ANOMALY.",
    )
    name = models.CharField("Название", max_length=128)
    severity = models.PositiveSmallIntegerField(
        "Тяжесть (1–5)",
        help_text="5 — критический.",
    )
    description = models.TextField("Описание", blank=True)

    class Meta:
        verbose_name = "Тип аномалии"
        verbose_name_plural = "Типы аномалий"

    def __str__(self) -> str:
        return f"{self.code} (severity={self.severity})"


class DetectedAnomaly(models.Model):
    """
    Результат гибридного анализа (ML + сигнатуры).
    """

    class DetectionMethod(models.TextChoices):
        ML = "ml", "ML (Isolation Forest)"
        SIGNATURE = "signature", "Сигнатурный"
        HYBRID = "hybrid", "Гибридный"

    class RiskLevel(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    log_entry = models.ForeignKey(
        LogEntry,
        on_delete=models.CASCADE,
        related_name="anomalies",
        verbose_name="Запись лога",
    )
    anomaly_type = models.ForeignKey(
        AnomalyType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="anomalies",
        verbose_name="Тип аномалии",
    )
    analysis_session = models.ForeignKey(
        AnalysisSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="anomalies",
        verbose_name="Сессия анализа",
    )

    detected_at = models.DateTimeField("Время обнаружения", default=timezone.now)
    detection_method = models.CharField(
        "Метод обнаружения",
        max_length=16,
        choices=DetectionMethod.choices,
        default=DetectionMethod.ML,
    )
    confidence_score = models.FloatField(
        "Уверенность (0–1)",
        help_text="Нормированная уверенность в аномальности.",
    )
    model_score = models.FloatField(
        "Score модели",
        null=True,
        blank=True,
        help_text="Сырое значение от Isolation Forest.",
    )
    explanation = models.TextField(
        "Объяснение",
        help_text="Почему запрос признан аномальным (прозрачность для пользователя).",
    )
    is_false_positive = models.BooleanField(
        "Ложное срабатывание",
        default=False,
    )
    risk_level = models.CharField(
        "Уровень риска",
        max_length=16,
        choices=RiskLevel.choices,
        default=RiskLevel.LOW,
        help_text="Нормализованный уровень риска: low/medium/high/critical.",
    )

    class Meta:
        verbose_name = "Обнаруженная аномалия"
        verbose_name_plural = "Обнаруженные аномалии"
        ordering = ["-detected_at"]

    def __str__(self) -> str:
        return f"Аномалия #{self.id} (log_entry_id={self.log_entry_id})"


class Alert(models.Model):
    """
    Уведомление для пользователя о важной/критической аномалии.
    """

    class Status(models.TextChoices):
        NEW = "new", "Новый"
        IN_PROGRESS = "in_progress", "В работе"
        FALSE_POSITIVE = "false_positive", "Ложное срабатывание"
        CASE = "case", "Дело"
        RESOLVED = "resolved", "Закрыт"

    class RiskLevel(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    anomaly = models.ForeignKey(
        DetectedAnomaly,
        on_delete=models.CASCADE,
        related_name="alerts",
        verbose_name="Аномалия",
    )
    recipient = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="alerts",
        verbose_name="Получатель",
    )
    created_at = models.DateTimeField("Создан", auto_now_add=True)
    status = models.CharField(
        "Статус",
        max_length=16,
        choices=Status.choices,
        default=Status.NEW,
    )
    message = models.TextField("Сообщение")
    risk_level = models.CharField(
        "Уровень риска",
        max_length=16,
        choices=RiskLevel.choices,
        default=RiskLevel.LOW,
        help_text="Нормализованный уровень риска алерта: low/medium/high/critical.",
    )

    class Meta:
        verbose_name = "Алерт"
        verbose_name_plural = "Алерты"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Alert #{self.id} ({self.status})"
