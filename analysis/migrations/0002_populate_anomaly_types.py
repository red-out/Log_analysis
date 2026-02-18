# Data migration: типы аномалий по умолчанию

from django.db import migrations


def create_anomaly_types(apps, schema_editor):
    AnomalyType = apps.get_model("analysis", "AnomalyType")
    types = [
        {"code": "SQLI", "name": "SQL-инъекция", "severity": 5, "description": "Обнаружены признаки SQL-инъекции в запросе."},
        {"code": "XSS", "name": "Cross-Site Scripting", "severity": 5, "description": "Обнаружены признаки XSS в запросе."},
        {"code": "STAT_ANOMALY", "name": "Статистическая аномалия", "severity": 3, "description": "Запрос отклоняется от нормального профиля (ML)."},
    ]
    for t in types:
        AnomalyType.objects.get_or_create(code=t["code"], defaults=t)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(create_anomaly_types, noop),
    ]
