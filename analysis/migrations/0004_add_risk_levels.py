from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0003_add_more_anomaly_types"),
    ]

    operations = [
        migrations.AddField(
            model_name="detectedanomaly",
            name="risk_level",
            field=models.CharField(
                choices=[("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")],
                default="low",
                help_text="Нормализованный уровень риска: low/medium/high/critical.",
                max_length=16,
                verbose_name="Уровень риска",
            ),
        ),
        migrations.AddField(
            model_name="alert",
            name="risk_level",
            field=models.CharField(
                choices=[("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")],
                default="low",
                help_text="Нормализованный уровень риска алерта: low/medium/high/critical.",
                max_length=16,
                verbose_name="Уровень риска",
            ),
        ),
    ]
