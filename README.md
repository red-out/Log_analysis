# Сервис сбора и анализа логов веб-сервера

Дипломный проект: обнаружение аномальных запросов с помощью **гибридного анализа** (сигнатурный поиск + unsupervised ML, Isolation Forest).  
Стек: **Django 4.2**, **Django REST Framework**, **PostgreSQL**, **Docker Compose**.

Подробное описание архитектуры, моделей и пайплайна — в [README_ARCHITECTURE.md](README_ARCHITECTURE.md).

---

## Требования

- **Python 3.10+**
- **PostgreSQL 16** (локально или через Docker)
- **Docker** и **Docker Compose** (рекомендуется)

---

## 1. Запуск через Docker (рекомендуется)

### Переменные окружения (опционально)

В корне есть **`.env.example`**. Скопируйте в `.env` и задайте `DJANGO_SECRET_KEY` и пароли БД для продакшена.

### Сборка и запуск

```bash
docker compose up --build
```

Поднимаются **web** (Django) и **db** (PostgreSQL), выполняются миграции.  
Приложение: **http://localhost:8000**

Создайте суперпользователя (один раз):

```bash
docker compose exec web python manage.py createsuperuser
```

### Данные между перезапусками

| Том | Содержимое |
|-----|------------|
| `postgres_data` | БД (логи, аномалии, сессии, пользователи) |
| `media_data` | ML-модель `isolation_forest.pkl`, медиа |

### Остановка

```bash
docker compose down          # контейнеры
docker compose down -v       # + удаление томов (БД и медиа)
```

### Команды внутри контейнера

```bash
docker compose exec web python manage.py train_model --min-samples 100 --contamination 0.05
docker compose exec web python manage.py import_logs_from_fs --path /app/sample_access_v8.log --created-by admin
```

Путь к файлу в контейнере — от корня образа (`/app/...`), код копируется при сборке (`COPY . /app/`).

---

## 2. Локальный запуск (без Docker)

Нужен PostgreSQL с учётными данными из `log_analysis/settings.py` или `.env`.

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
copy .env.example .env          # DB_HOST=localhost

mkdir media
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Веб-интерфейс: **http://127.0.0.1:8000/ui/**  
Админка: **http://127.0.0.1:8000/admin/**

Типы аномалий создаются миграциями (`0002`, `0003`, `0007` и др.).

---

## 3. Основные URL

| URL | Описание |
|-----|----------|
| http://localhost:8000/ui/ | Веб-интерфейс (дашборд, загрузка, алерты, статистика) |
| http://localhost:8000/ui/stats/ | Графики (только UI, без REST) |
| http://localhost:8000/admin/ | Django Admin |
| http://localhost:8000/api/schema/ | Swagger UI |
| http://localhost:8000/api/schema/redoc/ | ReDoc |
| POST http://localhost:8000/api/logs/upload/ | Загрузка лога (администратор) |
| http://localhost:8000/api/anomalies/ | Аномалии |
| http://localhost:8000/api/alerts/ | Алерты |
| http://localhost:8000/api/sessions/ | Сессии анализа |
| http://localhost:8000/api/log-entries/ | Записи логов |

---

## 4. Загрузка логов и анализ

Обработка выполняется единым модулем **`analysis/services/ingest.py`** (API, UI и CLI используют его).

1. Войдите в UI (`/ui/login/`) или используйте Basic Auth к API.
2. **POST** `/api/logs/upload/`:
   - **multipart**: поле `file` (`.log` / `.txt`), опционально `web_server_id`;
   - **raw body**: весь файл в теле; `?web_server_id=1` в query.

Пример:

```bash
curl -u admin:password -X POST -F "file=@./access.log" http://localhost:8000/api/logs/upload/
```

Ответ:

```json
{
  "session_id": 1,
  "logs_processed": 1500,
  "anomalies_detected": 12,
  "lines_skipped": 3
}
```

**`lines_skipped`** — строки с неверным форматом или ошибкой сохранения в БД.

### Логика детекции (кратко)

- Сохраняется `LogEntry` с признаками в `features`.
- Аномалия, если сработал **ML** (confidence ≥ 0.65) и/или **сигнатуры** (атака или мягкий сигнал).
- Метод: `hybrid` / `signature` / `ml`; тип из справочника `AnomalyType`; текст в `explanation`.
- **Alert** — при высоком/критическом риске или ML без класса атаки (medium).

### UI

- **Загрузка файла:** `/ui/upload/` (staff).
- **Импорт с диска:** `/ui/import/` (staff), путь в контейнере, напр. `/app/sample_access_v8.log`.

### CLI

```bash
python manage.py import_logs_from_fs --path ./access.log --created-by admin
python manage.py import_logs_from_fs --path /var/log/nginx --recursive --skip-analysis
```

| Флаг | Назначение |
|------|------------|
| `--web-server-id 1` | Привязка к `WebServer` |
| `--skip-analysis` | Только `LogEntry`, без детекции |
| `--recursive` | Обход каталога |

### Тестовые логи

Генератор: `scripts/generate_sample_access_logs.py` (смешение нормального трафика и атак, файлы `sample_access_v3.log` … `v12` в корне репозитория).

```bash
python scripts/generate_sample_access_logs.py --lines 1000
python scripts/generate_sample_access_logs.py --only 8 --lines 500
```

---

## 5. Обучение модели

```bash
python manage.py train_model --min-samples 100 --contamination 0.05
```

| Параметр | Смысл |
|----------|--------|
| `--min-samples` | Минимум строк **без атак** для обучения |
| `--contamination` | Гиперпараметр Isolation Forest (доля выбросов в train), не «грязность» файла |

Из обучения **исключаются** записи с `has_attack_signature=1` в `features`.

Файл модели: `media/models/isolation_forest.pkl` (в Docker — том `media_data`).

**Рекомендуемый порядок:**

1. Импорт с `--skip-analysis` (накопить нормальный трафик).
2. `train_model`.
3. Загрузка / импорт с полным анализом.

---

## 6. Структура проекта

```
.
├── manage.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── README_ARCHITECTURE.md
├── log_analysis/              # настройки Django
├── analysis/                  # модели, API, services, migrations
│   └── services/
│       ├── ingest.py          # единый пайплайн
│       ├── parser.py
│       ├── features.py
│       ├── ml_engine.py
│       └── risk.py
├── ui/                        # веб-интерфейс (templates)
└── scripts/                   # генератор sample-логов
```

---

## 7. Безопасность и лимиты

- Загрузка логов: throttle **10 запросов/мин** (`LogUploadThrottle`).
- Размер файла (multipart): до **20 MB**.
- API: **IsAuthenticated**; upload — **IsAdminUser**.
- Продакшен: `DJANGO_SECRET_KEY`, `DEBUG=false`, надёжные пароли БД.

---

## 8. Формат лога

**Nginx combined** и совместимый **Apache**:

```
127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

Другие форматы — расширение `analysis.services.parser`.

---
