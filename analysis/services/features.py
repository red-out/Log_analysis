"""
Извлечение признаков из распарсенных логов для ML и сигнатурный поиск.
Поддерживаются:
- SQLi
- XSS
- Path Traversal (LFI/RFI)
- Сканирование чувствительных файлов (.env, .git, /wp-admin и т.п.)
- Невалидные / редкие HTTP-методы (TRACE, TRACK, DEBUG, CONNECT и др.)
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict

from django.db.models import Count

from analysis.models import LogEntry

# Сигнатуры для детекции атак (упрощённые)
SQLI_PATTERN = re.compile(
    r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|--|\bOR\s+1\s*=\s*1|\bEXEC\b)",
    re.IGNORECASE,
)
XSS_PATTERN = re.compile(
    r"(<script\b|onerror\s*=|onload\s*=|javascript:|\balert\s*\()",
    re.IGNORECASE,
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|\\windows\\system32|/proc/self/environ)",
    re.IGNORECASE,
)
SENSITIVE_FILES_PATTERN = re.compile(
    r"(/\.env\b|/\.git\b|/wp-admin\b|/phpmyadmin\b|/backup\.sql\b|/config(\.php)?\b|/admin\b)",
    re.IGNORECASE,
)

SPECIAL_CHARS = set("?&=%<>\"'\\;()[]")

# Методы HTTP, которые считаем «нормальными» для большинства приложений.
ALLOWED_HTTP_METHODS = {
    "GET",
    "POST",
    "HEAD",
    "OPTIONS",
    "PUT",
    "PATCH",
    "DELETE",
}


def shannon_entropy(s: str) -> float:
    """
    Энтропия Шеннона для строки (мера «случайности»).
    Высокая энтропия часто характерна для обфусцированных payload.
    """
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def count_special_chars(s: str) -> int:
    """Количество спецсимволов в строке (часто выше в атаках)."""
    return sum(1 for ch in s if ch in SPECIAL_CHARS)


def ip_request_count(client_ip: str) -> int:
    """
    Количество записей с данным IP в БД (простая оценка частоты).
    В продакшене можно кэшировать или считать по временному окну.
    """
    return (
        LogEntry.objects.filter(client_ip=client_ip)
        .aggregate(c=Count("id"))
        .get("c")
        or 0
    )


def check_sqli(uri: str) -> bool:
    """Проверка URI на типичные паттерны SQL-инъекции."""
    return bool(SQLI_PATTERN.search(uri))


def check_xss(uri: str) -> bool:
    """Проверка URI на типичные паттерны XSS."""
    return bool(XSS_PATTERN.search(uri))


def check_path_traversal(uri: str) -> bool:
    """Path Traversal / LFI / RFI."""
    return bool(PATH_TRAVERSAL_PATTERN.search(uri))


def check_sensitive_file_scan(uri: str) -> bool:
    """Сканирование чувствительных файлов и админок."""
    return bool(SENSITIVE_FILES_PATTERN.search(uri))


def check_invalid_method(method: str) -> bool:
    """Невалидный / редкий HTTP-метод (TRACE, TRACK, DEBUG и др.)."""
    method = (method or "").upper()
    if not method:
        return False
    if method in ALLOWED_HTTP_METHODS:
        return False
    return True


def extract_features_from_parsed(
    client_ip: str,
    uri: str,
    user_agent: str,
    method: str,
) -> Dict[str, Any]:
    """
    Извлечь признаки для ML из распарсенной записи лога.

    :param client_ip: IP клиента.
    :param uri: URI запроса.
    :param user_agent: User-Agent.
    :param method: HTTP-метод.
    :return: Словарь с числовыми и флаговыми признаками.
    """
    uri_length = len(uri)
    uri_entropy = shannon_entropy(uri)
    special_char_count = count_special_chars(uri)
    ip_freq = ip_request_count(client_ip)

    has_sqli = check_sqli(uri)
    has_xss = check_xss(uri)
    has_path_traversal = check_path_traversal(uri)
    has_sensitive_file_scan = check_sensitive_file_scan(uri)
    has_invalid_http_method = check_invalid_method(method)
    has_any_signature = (
        has_sqli
        or has_xss
        or has_path_traversal
        or has_sensitive_file_scan
        or has_invalid_http_method
    )

    return {
        "uri_length": uri_length,
        "uri_entropy": uri_entropy,
        "special_char_count": special_char_count,
        "ip_request_count": ip_freq,
        "has_sqli_signature": int(has_sqli),
        "has_xss_signature": int(has_xss),
        "has_path_traversal_signature": int(has_path_traversal),
        "has_sensitive_file_scan_signature": int(has_sensitive_file_scan),
        "has_invalid_method": int(has_invalid_http_method),
        "has_any_signature": int(has_any_signature),
        "user_agent_len": min(len(user_agent), 512),
        "user_agent": user_agent[:255],
    }
