from django.db import migrations


def remove_high_request_rate_type(apps, schema_editor):
    AnomalyType = apps.get_model("analysis", "AnomalyType")
    AnomalyType.objects.filter(code="HIGH_REQUEST_RATE").delete()


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0007_expand_anomaly_types_owasp"),
    ]

    operations = [
        migrations.RunPython(remove_high_request_rate_type, noop),
    ]
