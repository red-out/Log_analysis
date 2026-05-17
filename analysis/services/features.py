"""
Извлечение признаков из распарсенных логов для ML и сигнатурный поиск.

Атаки (OWASP-ориентированные сигнатуры): SQLi, XSS, Path Traversal, CMD/RCE,
SSRF, LDAPi, XXE, open redirect, скан чувствительных путей, нетипичный метод.

Мягкие сигналы (low tier): подозрительный UA, длинный URI без payload.
"""
from __future__ import annotations

import math
import re
from urllib.parse import unquote_plus
from typing import Any, Dict


# ——— Пороги мягких сигналов ———
LONG_URI_PROBE_MIN_LENGTH = 180

# ——— Сигнатуры атак ———
SQLI_PATTERNS = [
    re.compile(
        r"(\bunion(?:\s+all)?\s+select\b|\bselect\s+.+\s+from\b|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
        re.IGNORECASE,
    ),
    re.compile(r"(--|/\*|\*/|#)", re.IGNORECASE),
    re.compile(
        r"(\binformation_schema\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\bpg_sleep\s*\(|\bwaitfor\s+delay\b)",
        re.IGNORECASE,
    ),
    re.compile(r"(\bexec(?:ute)?\b|\bxp_cmdshell\b|\bload_file\s*\()", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"(<script\b|</script>|<iframe\b|<svg\b|<img\b|<body\b)", re.IGNORECASE),
    re.compile(r"(javascript:|data:text/html|vbscript:)", re.IGNORECASE),
    re.compile(r"(onerror\s*=|onload\s*=|onmouseover\s*=|onclick\s*=|onfocus\s*=)", re.IGNORECASE),
    re.compile(r"(\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(|\bdocument\.cookie\b|\bwindow\.location\b)", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e%252e%252f)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self/environ|\\windows\\system32|boot\.ini|win\.ini)", re.IGNORECASE),
]

CMD_INJECTION_PATTERNS = [
    re.compile(r"(;\s*(ls|cat|wget|curl|bash|sh)\b|\|\||\$\(|\b/bin/(ba)?sh\b)", re.IGNORECASE),
    re.compile(r"(\bcmd\.exe\b|\bpowershell\b|\bwhoami\b|\bping\s+-c\b)", re.IGNORECASE),
    re.compile(r"(`[^`]+`|\$\{[^}]+\})", re.IGNORECASE),
]

SSRF_PATTERNS = [
    re.compile(r"(file://|gopher://|dict://)", re.IGNORECASE),
    re.compile(
        r"(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google)",
        re.IGNORECASE,
    ),
    re.compile(
        r"([?&](url|uri|dest|redirect|target|path)=https?%3a%2f%2f(127|localhost|0\.0))",
        re.IGNORECASE,
    ),
]

OPEN_REDIRECT_PATTERNS = [
    re.compile(
        r"([?&](url|redirect|next|goto|return|redir)=https?://)",
        re.IGNORECASE,
    ),
]

LDAP_INJECTION_PATTERNS = [
    re.compile(r"(\*\)|\(\||\(&|\(\|)", re.IGNORECASE),
    re.compile(r"(\buid=|\bobjectclass=|\bcn=).*[)(|*]", re.IGNORECASE),
]

XXE_PATTERNS = [
    re.compile(r"(<!ENTITY|<!DOCTYPE[^>]+SYSTEM|PUBLIC\s+[\"'][^\"']+[\"'])", re.IGNORECASE),
    re.compile(r"(%26lt;|%3c)!ENTITY", re.IGNORECASE),
]

SENSITIVE_FILES_PATTERNS = [
    re.compile(r"(/\.env\b|/\.git\b|/\.htaccess\b|/\.htpasswd\b)", re.IGNORECASE),
    re.compile(r"(/wp-admin\b|/wp-login\.php\b|/phpmyadmin\b|/admin\b|/manager/html\b)", re.IGNORECASE),
    re.compile(r"(/backup(?:_|-)?\d*\.sql\b|/dump\.sql\b|/config(?:\.php|\.yml|\.yaml|\.json)?\b)", re.IGNORECASE),
    re.compile(r"(/id_rsa\b|/authorized_keys\b|/docker-compose\.yml\b|/\.aws/credentials\b)", re.IGNORECASE),
]

SCANNER_UA_PATTERNS = [
    re.compile(
        r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|acunetix|nessus|burp|zgrab)",
        re.IGNORECASE,
    ),
    re.compile(r"^(curl|wget|python-requests|scrapy|libwww)", re.IGNORECASE),
]

SPECIAL_CHARS = set("?&=%<>\"'\\;()[]")

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
    return sum(1 for ch in s if ch in SPECIAL_CHARS)


def normalize_uri_for_detection(uri: str) -> str:
    if not uri:
        return ""
    normalized = uri.strip().lower()
    prev = normalized
    for _ in range(3):
        decoded = unquote_plus(prev)
        if decoded == prev:
            break
        prev = decoded
    return prev


def _match_patterns(normalized: str, patterns: list) -> bool:
    return any(p.search(normalized) for p in patterns)


def check_sqli(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), SQLI_PATTERNS)


def check_xss(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), XSS_PATTERNS)


def check_path_traversal(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), PATH_TRAVERSAL_PATTERNS)


def check_cmd_injection(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), CMD_INJECTION_PATTERNS)


def check_ssrf(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), SSRF_PATTERNS)


def check_open_redirect(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), OPEN_REDIRECT_PATTERNS)


def check_ldap_injection(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), LDAP_INJECTION_PATTERNS)


def check_xxe(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), XXE_PATTERNS)


def check_sensitive_file_scan(uri: str) -> bool:
    return _match_patterns(normalize_uri_for_detection(uri), SENSITIVE_FILES_PATTERNS)


def check_invalid_method(method: str) -> bool:
    method = (method or "").upper()
    if not method:
        return False
    return method not in ALLOWED_HTTP_METHODS


def check_unusual_user_agent(user_agent: str) -> bool:
    ua = (user_agent or "").strip()
    if len(ua) < 8:
        return True
    return any(p.search(ua) for p in SCANNER_UA_PATTERNS)


def check_long_uri_probe(uri: str, *, has_attack_signature: bool) -> bool:
    if has_attack_signature:
        return False
    return len(uri or "") >= LONG_URI_PROBE_MIN_LENGTH


def has_attack_signature_flags(
    *,
    has_sqli: bool,
    has_xss: bool,
    has_path_traversal: bool,
    has_cmd_injection: bool,
    has_ssrf: bool,
    has_open_redirect: bool,
    has_ldap_injection: bool,
    has_xxe: bool,
    has_sensitive_file_scan: bool,
    has_invalid_method: bool,
) -> bool:
    return any(
        [
            has_sqli,
            has_xss,
            has_path_traversal,
            has_cmd_injection,
            has_ssrf,
            has_open_redirect,
            has_ldap_injection,
            has_xxe,
            has_sensitive_file_scan,
            has_invalid_method,
        ]
    )


def extract_features_from_parsed(
    client_ip: str,
    uri: str,
    user_agent: str,
    method: str,
    *,
    ip_request_count: int = 0,
) -> Dict[str, Any]:
    uri_length = len(uri)
    uri_entropy = shannon_entropy(uri)
    special_char_count = count_special_chars(uri)
    ip_freq = int(ip_request_count)

    has_sqli = check_sqli(uri)
    has_xss = check_xss(uri)
    has_path_traversal = check_path_traversal(uri)
    has_cmd_injection = check_cmd_injection(uri)
    has_ssrf = check_ssrf(uri)
    has_open_redirect = check_open_redirect(uri)
    has_ldap_injection = check_ldap_injection(uri)
    has_xxe = check_xxe(uri)
    has_sensitive_file_scan = check_sensitive_file_scan(uri)
    has_invalid_http_method = check_invalid_method(method)

    has_attack = has_attack_signature_flags(
        has_sqli=has_sqli,
        has_xss=has_xss,
        has_path_traversal=has_path_traversal,
        has_cmd_injection=has_cmd_injection,
        has_ssrf=has_ssrf,
        has_open_redirect=has_open_redirect,
        has_ldap_injection=has_ldap_injection,
        has_xxe=has_xxe,
        has_sensitive_file_scan=has_sensitive_file_scan,
        has_invalid_method=has_invalid_http_method,
    )

    has_unusual_ua = check_unusual_user_agent(user_agent)
    has_long_uri_probe = check_long_uri_probe(uri, has_attack_signature=has_attack)

    has_soft_signal = has_unusual_ua or has_long_uri_probe

    return {
        "uri_length": uri_length,
        "uri_entropy": uri_entropy,
        "special_char_count": special_char_count,
        "ip_request_count": ip_freq,
        "has_sqli_signature": int(has_sqli),
        "has_xss_signature": int(has_xss),
        "has_path_traversal_signature": int(has_path_traversal),
        "has_cmd_injection_signature": int(has_cmd_injection),
        "has_ssrf_signature": int(has_ssrf),
        "has_open_redirect_signature": int(has_open_redirect),
        "has_ldap_injection_signature": int(has_ldap_injection),
        "has_xxe_signature": int(has_xxe),
        "has_sensitive_file_scan_signature": int(has_sensitive_file_scan),
        "has_invalid_method": int(has_invalid_http_method),
        "has_unusual_ua": int(has_unusual_ua),
        "has_long_uri_probe": int(has_long_uri_probe),
        "has_attack_signature": int(has_attack),
        "has_soft_signal": int(has_soft_signal),
        "user_agent_len": min(len(user_agent), 512),
    }
