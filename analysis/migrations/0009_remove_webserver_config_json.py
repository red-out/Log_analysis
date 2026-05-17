from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("analysis", "0008_remove_high_request_rate_type"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="webserver",
            name="config_json",
        ),
    ]
