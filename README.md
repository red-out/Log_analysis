# Сервис сбора и анализа логов веб-сервера

Дипломный проект: обнаружение аномальных запросов с помощью **гибридного анализа** (сигнатурный поиск + unsupervised ML, Isolation Forest). Развёртывание: Django + **PostgreSQL**, Docker Compose (рекомендуется).

---

## Требования

- **Python 3.10+**
- **PostgreSQL** (локально или через Docker)
- **Docker** и **Docker Compose** (рекомендуется для быстрого старта)

---

## 1. Запуск через Docker (рекомендуется)

### Шаг 1. Переменные окружения (опционально)

В корне репозитория есть **`.env.example`**. При необходимости скопируйте в `.env` и задайте `DJANGO_SECRET_KEY` и пароли БД для продакшена.

### Шаг 2. Сборка и запуск

В корне проекта:

```bash
docker-compose up --build
```

Выполняются миграции, поднимаются сервисы **web** и **db**. Приложение: **http://localhost:8000**

### Шаг 3. Данные между перезапусками

- **PostgreSQL** — том Docker `postgres_data` (данные БД не теряются при перезапуске).
- **Модели ML и медиа** — том `media_data` (каталог `/app/media` в контейнере).

### Шаг 4. Остановка

```bash
docker-compose down
```

Удалить контейнеры и тома (включая БД и медиа):

```bash
docker-compose down -v
```

### Служебные команды внутри контейнера

```bash
docker-compose exec web python manage.py train_model --min-samples 100
```

---

## 2. Локальный запуск (без Docker)

Нужен запущенный PostgreSQL и база с учётными данными, совпадающими с переменными окружения (по умолчанию см. `log_analysis/settings.py` и `.env.example`).

### Шаг 1. Виртуальное окружение и зависимости

Из **корня репозитория** (там же, где `manage.py`):

```bash
python -m venv .venv
.venv\Scripts\activate
# source .venv/bin/activate   # Linux/macOS

pip install -r requirements.txt
```

### Шаг 2. Переменные и каталог медиа

```bash
copy .env.example .env
# отредактируйте .env: DB_HOST=localhost, пароль БД и т.д.

mkdir media
```

Создайте в PostgreSQL пользователя и базу (имена как в `.env` / `settings.py`), затем:

```bash
python manage.py migrate
python manage.py createsuperuser
```

Типы аномалий при необходимости создаются миграцией `0002_populate_anomaly_types`; при отсутствии — через админку (**SQLI**, **XSS**, **STAT_ANOMALY** и др. по миграциям).

### Шаг 3. Запуск сервера

```bash
python manage.py runserver
```

Откройте в браузере: **http://127.0.0.1:8000/ui/** (веб-интерфейс) или **http://127.0.0.1:8000/admin/**.

---

## 3. Основные URL

| URL | Описание |
|-----|----------|
| **http://localhost:8000/ui/** | Веб-интерфейс (дашборд, загрузка логов, алерты, **статистика** `/ui/stats/`) |
| **http://localhost:8000/admin/** | Админ-панель Django |
| **http://localhost:8000/api/schema/** | Swagger UI (документация API) |
| **http://localhost:8000/api/schema/redoc/** | ReDoc |
| **http://localhost:8000/api/logs/upload/** | Загрузка лог-файла (POST, только администраторы) |
| **http://localhost:8000/api/anomalies/** | Обнаруженные аномалии |
| **http://localhost:8000/api/alerts/** | Алерты |
| **http://localhost:8000/api/sessions/** | Сессии анализа |
| **http://localhost:8000/api/log-entries/** | Записи логов |

Сводная статистика с графиками доступна в UI: **`/ui/stats/`** (отдельного REST-эндпоинта `/api/stats/` в проекте нет).

---

## 4. Загрузка логов и анализ

1. Войдите в систему (сессия/UI) или используйте Basic Auth к API.
2. **POST** `/api/logs/upload/`:
   - **`multipart/form-data`**: поле **file** — файл `.log` / `.txt` (Nginx/Apache combined), опционально **web_server_id**.
   - **Сырое тело** (`application/octet-stream` / `text/plain`): весь файл в теле запроса; `web_server_id` можно передать query-параметром `?web_server_id=1`.

Пример `curl` (после создания суперпользователя):

```bash
curl -u admin:password -X POST -F "file=@./path/to/access.log" http://localhost:8000/api/logs/upload/
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

Поле **`lines_skipped`** — число строк, которые не удалось разобрать как валидную запись combined или не удалось сохранить в БД (детали в логах сервера).

Для каждой успешно сохранённой строки: парсинг → признаки → Isolation Forest → при срабатывании ML/сигнатур создаётся `DetectedAnomaly` и при высоком риске — `Alert`. У аномалий в API есть поле **explanation**.

### Загрузка из файловой системы (CLI)

```bash
python manage.py import_logs_from_fs --path /var/log/nginx --recursive --created-by admin
```

Флаги:

- `--web-server-id 1` — привязка к `WebServer`;
- `--skip-analysis` — только сохранение `LogEntry` без детекции;
- один файл: `--path ./access.log`.

---

## 5. Обучение модели

```bash
python manage.py train_model --min-samples 100 --contamination 0.05
```

Модель: `media/models/isolation_forest.pkl` (в Docker — в томе `media_data`).

---

## 6. Структура проекта

```
.
├── manage.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── log_analysis/          # настройки Django
│   ├── settings.py
│   ├── urls.py
│   └── ...
├── analysis/              # модели, API, сервисы
│   ├── models.py
│   ├── views.py
│   ├── serializers.py
│   ├── urls.py
│   └── services/
│       ├── parser.py
│       ├── features.py
│       ├── ml_engine.py
│       ├── ingest.py
│       └── risk.py
├── ui/                    # веб-интерфейс
└── ...
```

---

## 7. Безопасность и лимиты

- Загрузка логов: **до 10 запросов в минуту** на эндпоинт (throttle).
- Размер файла в multipart: до **20 MB** (валидация в сериализаторе).
- API по умолчанию для **аутентифицированных** пользователей; загрузка логов — только **администраторы**.
- Для прода задайте **`DJANGO_SECRET_KEY`**, `DEBUG=false`, надёжные пароли БД (см. `.env.example`).

---

## 8. Формат лога

**Nginx combined** и совместимый **Apache**:

```
127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

Другие форматы — расширение `analysis.services.parser`.

---
