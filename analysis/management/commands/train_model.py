"""
Management-команда для обучения Isolation Forest на накопленных записях логов.
Использование: python manage.py train_model [--min-samples 100]
"""
from django.core.management.base import BaseCommand
from django.db.models import Count
from analysis.models import LogEntry
from analysis.services.ml_engine import IsolationForestEngine, FEATURE_ORDER


class Command(BaseCommand):
    help = "Обучить модель Isolation Forest на признаках из LogEntry (unsupervised)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--min-samples",
            type=int,
            default=100,
            help="Минимальное число записей для обучения (по умолчанию 100).",
        )
        parser.add_argument(
            "--contamination",
            type=float,
            default=0.05,
            help="Доля аномалий (contamination) для Isolation Forest (0.05 = 5%%).",
        )

    def handle(self, *args, **options):
        min_samples = options["min_samples"]
        contamination = options["contamination"]

        qs = LogEntry.objects.exclude(features={}).values("features")
        count = qs.count()
        if count < min_samples:
            self.stderr.write(
                self.style.WARNING(
                    f"Записей с признаками: {count}. Нужно минимум {min_samples}. "
                    "Загрузите логи через API или добавьте данные."
                )
            )
            return

        feature_dicts = []
        for row in qs.iterator():
            f = row.get("features") or {}
            if isinstance(f, dict):
                feature_dicts.append(f)
            if len(feature_dicts) >= 50000:  # ограничение по памяти
                break

        self.stdout.write(f"Обучение на {len(feature_dicts)} записях, contamination={contamination}...")
        engine = IsolationForestEngine(contamination=contamination)
        try:
            engine.fit(feature_dicts)
            self.stdout.write(self.style.SUCCESS(f"Модель сохранена: {engine.model_path}"))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Ошибка обучения: {e}"))
