"""
Импорт логов из файловой системы с запуском анализа.

Пример:
python manage.py import_logs_from_fs --path /var/log/nginx --recursive --created-by admin
"""
from __future__ import annotations

import time
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError
from django.utils import timezone

from analysis.models import WebServer
from analysis.services.parser import NginxAccessLogParser
from analysis.services.ingest import ingest_text, with_db_retry

User = get_user_model()

class Command(BaseCommand):
    help = "Импортировать .log/.txt файлы из файловой системы, распарсить и выполнить анализ."

    def add_arguments(self, parser):
        parser.add_argument("--path", required=True, help="Путь к файлу логов или директории.")
        parser.add_argument("--recursive", action="store_true", help="Рекурсивный поиск .log/.txt в директории.")
        parser.add_argument("--web-server-id", type=int, default=None, help="Опционально: ID WebServer.")
        parser.add_argument("--created-by", type=str, default=None, help="Username пользователя-создателя сессии.")
        parser.add_argument("--skip-analysis", action="store_true", help="Только загрузка логов без детекции аномалий.")

    def handle(self, *args, **options):
        source_path = Path(options["path"])
        if not source_path.exists():
            raise CommandError(f"Путь не существует: {source_path}")

        created_by = None
        if options["created_by"]:
            created_by = User.objects.filter(username=options["created_by"]).first()
            if created_by is None:
                raise CommandError(f"Пользователь не найден: {options['created_by']}")

        web_server = None
        if options["web_server_id"] is not None:
            web_server = WebServer.objects.filter(pk=options["web_server_id"]).first()
            if web_server is None:
                raise CommandError(f"WebServer с id={options['web_server_id']} не найден.")

        file_paths = self._collect_files(source_path, recursive=options["recursive"])
        if not file_paths:
            raise CommandError("Не найдено подходящих файлов (.log/.txt).")

        skip_analysis = bool(options["skip_analysis"])

        try:
            # Лёгкий DB healthcheck с retry
            with_db_retry(lambda: 1)
        except DatabaseError as e:
            raise CommandError(f"База данных недоступна: {e}") from e

        created_logs = 0
        created_anomalies = 0
        lines_skipped = 0
        last_session_id = None

        for file_path in file_paths:
            self.stdout.write(f"Обработка файла: {file_path}")
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                text = file_path.read_text(encoding="cp1251", errors="ignore")
            result = ingest_text(
                text=text,
                created_by=created_by,
                web_server=web_server,
                skip_analysis=skip_analysis,
            )
            last_session_id = result.session_id
            created_logs += result.logs_processed
            created_anomalies += result.anomalies_detected
            lines_skipped += result.lines_skipped

        self.stdout.write(
            self.style.SUCCESS(
                f"Готово. last_session_id={last_session_id}, logs_processed={created_logs}, "
                f"anomalies_detected={created_anomalies}, lines_skipped={lines_skipped}"
            )
        )

    def _collect_files(self, path: Path, recursive: bool) -> list[Path]:
        if path.is_file():
            if path.suffix.lower() in {".log", ".txt"}:
                return [path]
            return []
        if recursive:
            return sorted([p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".log", ".txt"}])
        return sorted([p for p in path.iterdir() if p.is_file() and p.suffix.lower() in {".log", ".txt"}])

    # Детекция/аномалии выполняются в analysis.services.ingest
