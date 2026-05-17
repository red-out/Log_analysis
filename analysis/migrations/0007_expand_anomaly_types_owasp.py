# Типы аномалий: OWASP-ориентированная severity, мягкие типы, ML без класса атаки

from django.db import migrations


def expand_anomaly_types(apps, schema_editor):
    AnomalyType = apps.get_model("analysis", "AnomalyType")

    # Актуализация severity существующих типов (только intrinsic, без ML)
    updates = {
        "STAT_ANOMALY": {
            "severity": 2,
            "description": (
                "Устаревший код: ранее — статистическая аномалия ML. "
                "Новые ML-срабатывания без сигнатуры → ML_UNCLASSIFIED."
            ),
        },
        "INVALID_METHOD": {
            "severity": 3,
            "description": "OWASP A05: нетипичные HTTP-методы (TRACE, TRACK, DEBUG и др.).",
        },
    }
    for code, fields in updates.items():
        AnomalyType.objects.filter(code=code).update(**fields)

    new_types = [
        {
            "code": "CMD_INJECTION",
            "name": "Command injection / RCE",
            "severity": 5,
            "description": "OWASP A03: признаки выполнения команд в URI (shell, cmd, pipe).",
        },
        {
            "code": "SSRF",
            "name": "Server-Side Request Forgery",
            "severity": 4,
            "description": "OWASP A10: обращение к внутренним хостам, metadata, file:// в параметрах.",
        },
        {
            "code": "OPEN_REDIRECT",
            "name": "Open Redirect",
            "severity": 3,
            "description": "OWASP A01: подозрительные параметры перенаправления (url=, redirect=, next=).",
        },
        {
            "code": "LDAP_INJECTION",
            "name": "LDAP Injection",
            "severity": 4,
            "description": "OWASP A03: паттерны LDAP-инъекции в URI.",
        },
        {
            "code": "XXE",
            "name": "XML External Entity (XXE)",
            "severity": 5,
            "description": "OWASP A05: сущности XML, SYSTEM/PUBLIC в запросе.",
        },
        {
            "code": "ML_UNCLASSIFIED",
            "name": "Не классифицировано (ML)",
            "severity": 3,
            "description": (
                "Поведенческая аномалия Isolation Forest без совпадения сигнатур. "
                "Сценарий zero-day / неизвестный паттерн — требует ручной проверки."
            ),
        },
        {
            "code": "UNUSUAL_UA",
            "name": "Подозрительный User-Agent",
            "severity": 1,
            "description": "OWASP A05: пустой, сканерный или нетипичный User-Agent.",
        },
        {
            "code": "LONG_URI_PROBE",
            "name": "Длинный URI без сигнатуры атаки",
            "severity": 1,
            "description": "Разведка / фаззинг: очень длинный URI без известных payload.",
        },
    ]
    for t in new_types:
        AnomalyType.objects.get_or_create(code=t["code"], defaults=t)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0006_delete_report"),
    ]

    operations = [
        migrations.RunPython(expand_anomaly_types, noop),
    ]
