# Сервис сбора и анализа логов веб-сервера

Дипломный проект: обнаружение аномальных запросов с помощью **гибридного анализа** (сигнатурный поиск + Unsupervised ML, Isolation Forest). Self-contained развёртывание на SQLite, без кластеров.

---

## Требования

- **Python 3.10+**
- Либо **Docker** и **Docker Compose** (рекомендуется)

---

## 1. Запуск через Docker (рекомендуется)

### Шаг 1. Сборка и запуск

В корне проекта выполните:

```bash
docker-compose up --build
```

При первом запуске будут выполнены миграции БД и созданы директории для данных. Сервис будет доступен по адресу: **http://localhost:8000**

### Шаг 2. Данные между перезапусками

- База SQLite хранится в Docker volume `db_data` (файл `db/db.sqlite3` не теряется при перезапуске контейнера).
- Модели ML и медиа — в volume `media_data`.

### Шаг 3. Остановка

```bash
docker-compose down
```

Чтобы удалить и тома с данными:

```bash
docker-compose down -v
```

---

## 2. Локальный запуск (без Docker)

### Шаг 1. Виртуальное окружение и зависимости

```bash
cd log_analysis
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate   # Linux/macOS

pip install -r requirements.txt
```

### Шаг 2. Директории для БД и медиа

```bash
mkdir db media
```

### Шаг 3. Миграции и суперпользователь

```bash
python manage.py migrate
python manage.py createsuperuser
```

При необходимости создайте типы аномалий (если миграция `0002_populate_anomaly_types` уже применена — они создадутся автоматически). Иначе создайте их в админке: **SQLI**, **XSS**, **STAT_ANOMALY**.

### Шаг 4. Запуск сервера

```bash
python manage.py runserver
```

Откройте в браузере: **http://127.0.0.1:8000**

---

## 3. Основные URL

| URL | Описание |
|-----|----------|
| **http://localhost:8000/admin/** | Админ-панель Django (логи, аномалии, алерты) |
| **http://localhost:8000/api/schema/** | Swagger UI (документация API) |
| **http://localhost:8000/api/schema/redoc/** | ReDoc |
| **http://localhost:8000/api/logs/upload/** | Загрузка лог-файла (POST, только для админов) |
| **http://localhost:8000/api/anomalies/** | Список обнаруженных аномалий |
| **http://localhost:8000/api/alerts/** | Алерты |
| **http://localhost:8000/api/sessions/** | Сессии анализа |
| **http://localhost:8000/api/log-entries/** | Записи логов |
| **http://localhost:8000/api/stats/** | Сводная статистика |

---

## 4. Загрузка логов и анализ

1. Войдите в админку или используйте Basic Auth.
2. Отправьте **POST** запрос на `/api/logs/upload/` с телом `multipart/form-data`:
   - **file** — файл с логами (формат Nginx/Apache combined, расширение `.log` или `.txt`).
   - **web_server_id** (опционально) — ID веб-сервера из справочника.

В корне проекта лежит пример файла **sample_access.log** — его можно использовать для проверки (в т.ч. есть строки с признаками SQLi и XSS).

Пример через `curl` (после создания суперпользователя `admin` / `password`):

```bash
curl -u admin:password -X POST -F "file=@sample_access.log" http://localhost:8000/api/logs/upload/
```

Ответ:

```json
{
  "session_id": 1,
  "logs_processed": 1500,
  "anomalies_detected": 12
}
```

При загрузке для каждой строки:
- парсится лог (Nginx/Apache combined);
- извлекаются признаки (длина URI, энтропия, спецсимволы, частота IP, сигнатуры SQLi/XSS);
- выполняется предсказание Isolation Forest;
- при аномалии или срабатывании сигнатуры создаётся запись в «Обнаруженные аномалии» и при высокой тяжести — алерт. В ответах API у аномалий всегда есть поле **explanation**.

---

## 5. Обучение модели на накопленных данных

После того как в БД накопилось достаточно записей с заполненным полем `features`, можно переобучить Isolation Forest:

```bash
python manage.py train_model --min-samples 100 --contamination 0.05
```

В Docker:

```bash
docker-compose exec web python manage.py train_model --min-samples 100
```

Модель сохраняется в `media/models/isolation_forest.pkl` и используется при следующих загрузках логов.

---

## 6. Структура проекта

```
log_analysis/
├── manage.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── log_analysis/           # настройки проекта
│   ├── settings.py
│   ├── urls.py
│   └── ...
└── analysis/               # приложение
    ├── models.py           # LogEntry, DetectedAnomaly, Alert, AnalysisSession, ...
    ├── admin.py
    ├── views.py            # API: загрузка логов, аномалии, алерты, статистика
    ├── serializers.py
    ├── urls.py
    ├── services/
    │   ├── parser.py       # парсинг Nginx/Apache access.log
    │   ├── features.py     # признаки + сигнатуры SQLi/XSS
    │   └── ml_engine.py    # Isolation Forest, объяснения
    └── management/commands/
        └── train_model.py  # обучение модели по данным из БД
```

---

## 7. Безопасность и лимиты

- Загрузка логов: **rate limit 10 запросов в минуту** на эндпоинт загрузки.
- Размер файла: до **20 MB**.
- Доступ к API: только для **аутентифицированных** пользователей; загрузка логов — только для **администраторов**.

---

## 8. Формат лога

Поддерживается формат **Nginx combined** и аналогичный **Apache**:

```
127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

Для других форматов можно расширить `analysis.services.parser` (новый класс парсера и вызов из view).

---

