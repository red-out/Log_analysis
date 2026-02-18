# Generated manually for analysis app

from django.conf import settings
from django.db import migrations, models
from django.utils import timezone
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="WebServer",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=150, unique=True, verbose_name="Название")),
                ("config_json", models.JSONField(blank=True, default=dict, help_text="Параметры парсинга и метаданные (формат лога, таймзона и т.д.).", verbose_name="Конфиг парсинга")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"verbose_name": "Веб-сервер", "verbose_name_plural": "Веб-серверы"},
        ),
        migrations.CreateModel(
            name="AnalysisSession",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("start_time", models.DateTimeField(default=timezone.now, verbose_name="Начало")),
                ("end_time", models.DateTimeField(blank=True, null=True, verbose_name="Конец")),
                ("model_version", models.CharField(blank=True, max_length=64, verbose_name="Версия модели")),
                ("logs_processed_count", models.PositiveIntegerField(default=0, verbose_name="Обработано записей")),
                ("anomalies_count", models.PositiveIntegerField(default=0, verbose_name="Найдено аномалий")),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="analysis_sessions", to=settings.AUTH_USER_MODEL)),
            ],
            options={"verbose_name": "Сессия анализа", "verbose_name_plural": "Сессии анализа", "ordering": ["-start_time"]},
        ),
        migrations.CreateModel(
            name="AnomalyType",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(help_text="Напр. SQLI, XSS, STAT_ANOMALY.", max_length=32, unique=True, verbose_name="Код")),
                ("name", models.CharField(max_length=128, verbose_name="Название")),
                ("severity", models.PositiveSmallIntegerField(help_text="5 — критический.", verbose_name="Тяжесть (1–5)")),
                ("description", models.TextField(blank=True, verbose_name="Описание")),
            ],
            options={"verbose_name": "Тип аномалии", "verbose_name_plural": "Типы аномалий"},
        ),
        migrations.CreateModel(
            name="LogEntry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("timestamp", models.DateTimeField(db_index=True, verbose_name="Время")),
                ("client_ip", models.GenericIPAddressField(db_index=True, verbose_name="IP клиента")),
                ("method", models.CharField(max_length=10, verbose_name="Метод")),
                ("uri", models.TextField(verbose_name="URI")),
                ("status_code", models.PositiveIntegerField(verbose_name="Код ответа")),
                ("user_agent", models.TextField(blank=True, verbose_name="User-Agent")),
                ("raw_line", models.TextField(verbose_name="Исходная строка")),
                ("features", models.JSONField(blank=True, default=dict, help_text="Извлечённые числовые/категориальные признаки.", verbose_name="Признаки для ML")),
                ("analysis_session", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="log_entries", to="analysis.analysissession", verbose_name="Сессия анализа")),
                ("web_server", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="log_entries", to="analysis.webserver", verbose_name="Веб-сервер")),
            ],
            options={"verbose_name": "Запись лога", "verbose_name_plural": "Записи логов", "ordering": ["-timestamp"]},
        ),
        migrations.CreateModel(
            name="DetectedAnomaly",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("detected_at", models.DateTimeField(default=timezone.now, verbose_name="Время обнаружения")),
                ("detection_method", models.CharField(choices=[("ml", "ML (Isolation Forest)"), ("signature", "Сигнатурный"), ("hybrid", "Гибридный")], default="ml", max_length=16, verbose_name="Метод обнаружения")),
                ("confidence_score", models.FloatField(help_text="Нормированная уверенность в аномальности.", verbose_name="Уверенность (0–1)")),
                ("model_score", models.FloatField(blank=True, help_text="Сырое значение от Isolation Forest.", null=True, verbose_name="Score модели")),
                ("explanation", models.TextField(help_text="Почему запрос признан аномальным (прозрачность для пользователя).", verbose_name="Объяснение")),
                ("is_false_positive", models.BooleanField(default=False, verbose_name="Ложное срабатывание")),
                ("analysis_session", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="anomalies", to="analysis.analysissession", verbose_name="Сессия анализа")),
                ("anomaly_type", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="anomalies", to="analysis.anomalytype", verbose_name="Тип аномалии")),
                ("log_entry", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="anomalies", to="analysis.logentry", verbose_name="Запись лога")),
            ],
            options={"verbose_name": "Обнаруженная аномалия", "verbose_name_plural": "Обнаруженные аномалии", "ordering": ["-detected_at"]},
        ),
        migrations.CreateModel(
            name="Alert",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, verbose_name="Создан")),
                ("status", models.CharField(choices=[("new", "Новый"), ("in_progress", "В работе"), ("resolved", "Закрыт")], default="new", max_length=16, verbose_name="Статус")),
                ("message", models.TextField(verbose_name="Сообщение")),
                ("anomaly", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="alerts", to="analysis.detectedanomaly", verbose_name="Аномалия")),
                ("recipient", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="alerts", to=settings.AUTH_USER_MODEL, verbose_name="Получатель")),
            ],
            options={"verbose_name": "Алерт", "verbose_name_plural": "Алерты", "ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="Report",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("generated_at", models.DateTimeField(auto_now_add=True, verbose_name="Создан")),
                ("summary", models.JSONField(default=dict, help_text="Статистика по типам аномалий, периодам и т.д.", verbose_name="Сводка")),
                ("pdf_path", models.CharField(blank=True, max_length=512, verbose_name="Путь к PDF")),
                ("generated_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="reports", to=settings.AUTH_USER_MODEL)),
            ],
            options={"verbose_name": "Отчёт", "verbose_name_plural": "Отчёты", "ordering": ["-generated_at"]},
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["timestamp", "client_ip"], name="analysis_lo_timesta_8c0b0d_idx"),
        ),
        migrations.AddIndex(
            model_name="logentry",
            index=models.Index(fields=["-timestamp"], name="analysis_lo_timesta_2a2b2c_idx"),
        ),
    ]
