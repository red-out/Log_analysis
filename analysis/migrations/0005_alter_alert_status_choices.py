from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0004_add_risk_levels"),
    ]

    operations = [
        migrations.AlterField(
            model_name="alert",
            name="status",
            field=models.CharField(
                choices=[
                    ("new", "Новый"),
                    ("in_progress", "В работе"),
                    ("false_positive", "Ложное срабатывание"),
                    ("case", "Дело"),
                    ("resolved", "Закрыт"),
                ],
                default="new",
                max_length=16,
                verbose_name="Статус",
            ),
        ),
    ]
