from django.db import migrations


def create_more_anomaly_types(apps, schema_editor):
    AnomalyType = apps.get_model("analysis", "AnomalyType")
    types = [
        {
            "code": "PATH_TRAVERSAL",
            "name": "Path Traversal / LFI",
            "severity": 5,
            "description": "Обнаружены признаки обхода директорий или локального включения файлов (../, /etc/passwd и т.п.).",
        },
        {
            "code": "SENSITIVE_FILE_SCAN",
            "name": "Сканирование чувствительных файлов",
            "severity": 4,
            "description": "Попытки доступа к .env, .git, /wp-admin, /phpmyadmin, backup.sql и другим чувствительным ресурсам.",
        },
        {
            "code": "INVALID_METHOD",
            "name": "Невалидный HTTP-метод",
            "severity": 3,
            "description": "Используются нетипичные HTTP-методы (TRACE, TRACK, DEBUG, CONNECT и др.).",
        },
    ]
    for t in types:
        AnomalyType.objects.get_or_create(code=t["code"], defaults=t)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0002_populate_anomaly_types"),
    ]

    operations = [
        migrations.RunPython(create_more_anomaly_types, noop),
    ]

