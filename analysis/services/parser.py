"""
Парсинг access.log (Nginx combined, опционально Apache).
Одна строка -> ParsedLogLine; создание LogEntry с извлечением признаков.
"""
from __future__ import annotations

import datetime as dt
import logging
import re
from dataclasses import dataclass
from typing import Optional

from django.utils import timezone

from analysis.models import LogEntry, WebServer
from analysis.services.features import extract_features_from_parsed

logger = logging.getLogger(__name__)

# Nginx combined: 127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
NGINX_COMBINED_RE = re.compile(
    r"(?P<ip>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)\s+"
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)

# Apache combined (похожий формат)
APACHE_COMBINED_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>[^"]*)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


@dataclass
class ParsedLogLine:
    """Распарсенная одна строка access.log."""

    timestamp: dt.datetime
    client_ip: str
    method: str
    uri: str
    status_code: int
    user_agent: str
    raw_line: str


class NginxAccessLogParser:
    """
    Парсер Nginx access.log в формате combined.
    Поддерживает таймзону в логе (например +0000).
    """

    time_format: str = "%d/%b/%Y:%H:%M:%S %z"

    def parse_line(self, line: str) -> Optional[ParsedLogLine]:
        """
        Разобрать одну строку лога.

        :param line: Строка из файла.
        :return: ParsedLogLine или None при ошибке/пустой строке.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        match = NGINX_COMBINED_RE.match(line)
        if not match:
            # Пробуем Apache
            match = APACHE_COMBINED_RE.match(line)
        if not match:
            logger.debug("Unmatched log line: %s", line[:100])
            return None

        try:
            raw_time = match.group("time")
            # Убираем пробел перед +0000 для strptime
            if " " in raw_time and raw_time[-5] in "+-":
                ts = dt.datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S %z")
            else:
                ts = dt.datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S")
                ts = timezone.make_aware(ts) if timezone.is_naive(ts) else ts
        except (KeyError, ValueError) as e:
            logger.warning("Timestamp parse error '%s': %s", raw_time, e)
            ts = timezone.now()

        try:
            status_code = int(match.group("status"))
        except (KeyError, ValueError):
            status_code = 0

        uri = match.group("uri")
        if not uri or len(uri) > 8192:
            logger.debug("Skip line: invalid uri length")
            return None

        return ParsedLogLine(
            timestamp=ts,
            client_ip=match.group("ip"),
            method=match.group("method"),
            uri=uri,
            status_code=status_code,
            user_agent=match.group("user_agent"),
            raw_line=line,
        )

    def create_log_entry(
        self,
        parsed: ParsedLogLine,
        web_server: Optional[WebServer] = None,
        analysis_session=None,
        ip_counts: dict[str, int] | None = None,
    ) -> LogEntry:
        """
        Создать и сохранить LogEntry с извлечёнными признаками.

        :param ip_counts: счётчик запросов по IP в рамках текущего ingest (без запросов в БД).

        :raises ValueError: при невалидных данных после full_clean.
        """
        if ip_counts is not None:
            ip_request_count = ip_counts.get(parsed.client_ip, 0)
            ip_counts[parsed.client_ip] = ip_request_count + 1
        else:
            ip_request_count = 0

        features = extract_features_from_parsed(
            client_ip=parsed.client_ip,
            uri=parsed.uri,
            user_agent=parsed.user_agent,
            method=parsed.method,
            ip_request_count=ip_request_count,
        )
        entry = LogEntry(
            web_server=web_server,
            analysis_session=analysis_session,
            timestamp=parsed.timestamp,
            client_ip=parsed.client_ip,
            method=parsed.method,
            uri=parsed.uri,
            status_code=parsed.status_code,
            user_agent=parsed.user_agent,
            raw_line=parsed.raw_line,
            features=features,
        )
        entry.full_clean()
        entry.save()
        return entry
