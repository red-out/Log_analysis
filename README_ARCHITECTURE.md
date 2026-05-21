# Архитектура проекта Log_analysis

Дипломный проект: **сбор и анализ access-логов веб-сервера для обнаружения аномальных запросов**.

Стек: **Django 4.2**, **Django REST Framework**, **PostgreSQL 16**, **scikit-learn** (Isolation Forest), **Docker Compose**.  
Веб-интерфейс: **Django Templates** (без отдельного SPA). Документация API: **drf-spectacular** (OpenAPI 3, Swagger/ReDoc).

---

## 1. Назначение и ключевые свойства

- **Гибридный анализ**: сигнатурные правила (OWASP-ориентированные паттерны) + unsupervised ML (Isolation Forest).
- **Единый пайплайн обработки** (`analysis/services/ingest.py`) для UI, REST API и CLI — логика не дублируется.
- **Интерпретируемость**: у каждой `DetectedAnomaly` есть поле `explanation`.
- **Развёртывание**: Django-приложение + PostgreSQL в Docker Compose; ML-модель на диске в `media/models/`.

---

## 2. Слои системы

| Слой | Расположение | Назначение |
|------|--------------|------------|
| Хранение | `analysis/models.py`, PostgreSQL | Сущности, связи, индексы |
| Доменная логика | `analysis/services/` | Парсинг, признаки, ML, ingest, риск |
| REST API | `analysis/views.py`, `serializers.py`, `urls.py` | JSON для внешних клиентов |
| UI | `ui/views.py`, `ui/templates/` | HTML-интерфейс оператора |
| Админка | `analysis/admin.py` | Управление данными |
| CLI | `analysis/management/commands/` | `train_model`, `import_logs_from_fs` |
| Инфраструктура | `log_analysis/settings.py`, `Dockerfile`, `docker-compose.yml` | Конфигурация и контейнеры |

### Маршрутизация URL

- `log_analysis/urls.py` — корень: `/admin/`, `/api/`, `/ui/`, Swagger.
- `analysis/urls.py` — REST под префиксом `/api/`.
- `ui/urls.py` — страницы под префиксом `/ui/`.

---

## 3. Модель данных

### 3.1. `WebServer`

Справочник источников логов: `name`, `created_at`.

### 3.2. `AnalysisSession`

Один прогон обработки (загрузка файла / импорт):

- `start_time`, `end_time`, `model_version`
- `logs_processed_count`, `anomalies_count`
- `created_by` → `auth_user`

### 3.3. `LogEntry`

Одна распарсенная строка access.log:

- `timestamp`, `client_ip` (индексы), `method`, `uri`, `status_code`, `user_agent`, `raw_line`
- `features` (JSONB) — признаки для ML и флаги сигнатур
- `web_server`, `analysis_session` (FK, nullable)

Индексы: `(timestamp, client_ip)`, `(-timestamp)`.

### 3.4. `AnomalyType`

Справочник типов (`code`, `name`, `severity` 1–5, `description`). Заполняется миграциями.

Примеры кодов:

| Код | Severity (типично) | Категория |
|-----|-------------------|-----------|
| SQLI, XSS, XXE, CMD_INJECTION | 5 | Атаки |
| SSRF, LDAP_INJECTION, PATH_TRAVERSAL, SENSITIVE_FILE_SCAN | 4 | Атаки |
| OPEN_REDIRECT, INVALID_METHOD, ML_UNCLASSIFIED | 3 | Средние / ML |
| UNUSUAL_UA, LONG_URI_PROBE | 1 | Мягкие сигналы |
| STAT_ANOMALY | 2 | Legacy fallback для ML |

### 3.5. `DetectedAnomaly`

Результат детекции на одну `LogEntry`:

- `detection_method`: `ml` | `signature` | `hybrid`
- `confidence_score` (0–1), `model_score`, `explanation`
- `risk_level`: `low` / `medium` / `high` / `critical` — из **severity** типа (`risk.py`), не из ML confidence
- `is_false_positive`, `anomaly_type`, `analysis_session`

### 3.6. `Alert`

Уведомление аналитику: `anomaly`, `recipient`, `status`, `message`, `risk_level`.

Статусы: `new`, `in_progress`, `false_positive`, `case`, `resolved`.

Служебные таблицы Django: `auth_user`, `django_session`, `django_migrations` и др.

---

## 4. Пайплайн ingest (`analysis/services/ingest.py`)

Единая точка входа: **`ingest_text()`** → **`ingest_parsed_lines()`**.

Вызывается из:

- `POST /api/logs/upload/` (`LogUploadView`)
- `ui/views.upload_logs`, `import_from_fs`
- `manage.py import_logs_from_fs`

### Шаги для каждой строки

1. **`parser.create_log_entry()`** — парсинг уже выполнен; сохранение `LogEntry` + `features`.
2. Счётчик **`ip_request_count`** ведётся в памяти за текущую загрузку (`ip_counts`), без запроса в БД на каждую строку.
3. **`IsolationForestEngine.predict(features)`** — ML-оценка.
4. Правила: `has_attack_signature`, `has_soft_signal` (из `features`).
5. Аномалия, если **ML** (`is_anomaly` и `confidence_score ≥ 0.65`) **или** есть rule signal.
6. Метод: ML + правила → `hybrid`; только правила → `signature`; только ML → `ml`.
7. **`_resolve_anomaly_type()`** — приоритет кодов атак, затем мягких; только ML → `ML_UNCLASSIFIED`.
8. **`calculate_risk_level(severity)`** — уровень риска.
9. Создание **`DetectedAnomaly`**; при политике — **`Alert`**.

Опция **`skip_analysis`**: только сохранение `LogEntry` (для накопления данных перед `train_model`).

---

## 5. Признаки и сигнатуры (`features.py`)

### Числовые признаки (вектор ML, `FEATURE_ORDER`)

- `uri_length`, `uri_entropy`, `special_char_count`
- `ip_request_count` — порядковый номер запроса IP **в текущей сессии ingest**
- `user_agent_len`

### Флаги атак (0/1)

SQLi, XSS, path traversal, CMD injection, SSRF, LDAP, XXE, open redirect, sensitive file scan, invalid HTTP method → сводный **`has_attack_signature`**.

### Мягкие сигналы

- **`has_unusual_ua`** — пустой/сканерный User-Agent
- **`has_long_uri_probe`** — URI ≥ 180 символов без сигнатуры атаки → **`has_soft_signal`**

URI нормализуется: lower + до 3× URL-decode (`normalize_uri_for_detection`).

---

## 6. ML (`ml_engine.py`)

- Модель: **Isolation Forest** (sklearn), файл `media/models/isolation_forest.pkl`.
- **`contamination`** (по умолчанию 0.05) — гиперпараметр sklearn (ожидаемая доля выбросов в **обучающей** выборке), не «процент грязи в файле».
- Команда **`train_model`**: обучение на `LogEntry.features`; строки с **`has_attack_signature=1` исключаются**; до 50 000 записей.
- Если модель не обучена: `predict` возвращает нулевую уверенность, в `explanation` указано, что работают сигнатуры.

---

## 7. REST API

| Метод | URL | Описание |
|-------|-----|----------|
| POST | `/api/logs/upload/` | Загрузка лога (admin), throttle 10/min |
| GET | `/api/anomalies/` | Список аномалий |
| GET/PATCH | `/api/alerts/` | Алерты |
| GET | `/api/sessions/` | Сессии анализа |
| GET | `/api/log-entries/` | Записи логов |

Аутентификация: Session + Basic. Загрузка логов: **IsAdminUser**.

**Статистика с графиками** — только UI: `/ui/stats/` (отдельного `/api/stats/` нет).

Swagger: `/api/schema/`, ReDoc: `/api/schema/redoc/`.

---

## 8. Веб-интерфейс (`ui/`)

| URL | Назначение |
|-----|------------|
| `/ui/` | Дашборд |
| `/ui/upload/` | Загрузка файла (staff) |
| `/ui/import/` | Импорт с диска (staff) |
| `/ui/anomalies/`, `/ui/alerts/` | Просмотр результатов |
| `/ui/stats/` | Графики (Chart.js) |
| `/ui/sessions/`, `/ui/log-entries/`, `/ui/web-servers/` | Списки |

Сессии Django: cookie `sessionid`, данные в таблице **`django_session`** (PostgreSQL).

---

## 9. Инфраструктура

### `settings.py`

- БД: PostgreSQL (`DB_HOST`, `DB_NAME`, …).
- `MEDIA_ROOT` / `ML_MODELS_DIR` — модель ML.
- DRF + `drf-spectacular`, django-filter, CORS (в DEBUG).

### Docker Compose

- **`db`**: `postgres:16`, том `postgres_data`.
- **`web`**: сборка из `Dockerfile`, порт `8000`, том `media_data` → `/app/media`, `DB_HOST=db`.

Код приложения в образе (`COPY . /app/`); примеры логов в контейнере: `/app/...` после сборки.

---

## 10. Рекомендуемый сценарий ML

1. Импорт «нормального» трафика: `import_logs_from_fs --skip-analysis`.
2. `train_model --min-samples 100 --contamination 0.05`.
3. Импорт / upload с полным анализом — гибридная детекция с обученной моделью.

---

## 11. Структура каталогов

```
log_analysis/     # settings, urls, wsgi
analysis/         # models, api, services, migrations, management
ui/               # views, templates, static
scripts/          # generate_sample_access_logs.py
```

Подробный запуск и примеры команд — в [README.md](README.md).
