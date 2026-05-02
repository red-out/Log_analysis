from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0005_alter_alert_status_choices"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Report",
        ),
    ]
