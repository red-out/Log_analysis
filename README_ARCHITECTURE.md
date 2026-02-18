## Описание проекта и архитектуры

### 1. Назначение системы

Сервис реализует дипломный проект по теме:  
**«Сбор и анализ логов веб‑сервера для обнаружения аномальных запросов»**.

Ключевые особенности:

- **Гибридный анализ**: сигнатурный поиск + unsupervised ML (Isolation Forest).
- **Self-contained развертывание**: одна Django‑сервис, база — SQLite (файл `db.sqlite3`), без отдельных кластеров.
- **Интерпретируемость**: в каждом объекте `DetectedAnomaly` есть поле `explanation` с человекопонятным объяснением, почему запрос был признан аномальным.

Основная задача: принимать access‑логи (Nginx/Apache), нормализовать их, выделять признаки, находить аномалии и предоставлять удобный API и админку для анализа.

---

### 2. Высокоуровневая архитектура

Система логически разделена на несколько слоев:

- **Хранение данных (Django models + SQLite)** — описание сущностей и индексов.
- **Парсинг и извлечение признаков (`analysis/services`)** — доменная логика по работе с логами.
- **ML‑движок (`ml_engine.py`)** — обучение и предсказание Isolation Forest.
- **REST API (`views.py`, `serializers.py`, `urls.py`)** — внешние эндпоинты.
- **Администрирование и служебные операции** — `admin.py`, `management/commands`.
- **Инфраструктура** — настройки Django, Docker, docker-compose.

---

### 3. Модель данных (основные сущности)

#### 3.1. `WebServer`

Справочник источников логов (веб‑серверов).

- `name` — человекочитаемое имя.
- `config_json` — JSON с параметрами парсинга и метаданными (формат лога, таймзона и т.п.).

Используется для привязки записей лога к конкретному серверу и возможной дальнейшей кастомизации парсинга.

#### 3.2. `AnalysisSession`

Одна сессия анализа — фактически один запуск обработки лог‑файла.

- `start_time`, `end_time` — временные метки.
- `model_version` — версия ML‑модели, применённой при анализе.
- `logs_processed_count` — сколько строк лога обработано.
- `anomalies_count` — сколько аномалий найдено.
- `created_by` — пользователь, инициировавший анализ.

Позволяет видеть историю запусков и статистику по каждому запуску.

#### 3.3. `LogEntry`

Нормализованная запись access.log (одна строка).

Основные поля:

- `timestamp` — время запроса (**индексировано**, важно для временных запросов).
- `client_ip` — IP клиента (**индексировано**, важно для поиска по IP).
- `method`, `uri`, `status_code`, `user_agent`, `raw_line`.
- `features` — `JSONField` с извлечёнными признаками (для ML и сигнатурного анализа).
- `web_server`, `analysis_session` — связи с источником и сессией анализа.

На уровне БД заданы индексы:

- по `timestamp`;
- по `client_ip`;
- составной индекс `timestamp + client_ip`.

#### 3.4. `AnomalyType`

Справочник типов аномалий, объединяющий сигнатурные и ML‑аномалии:

- `SQLI` — SQL‑инъекции,
- `XSS` — XSS‑атаки,
- `STAT_ANOMALY` — статистическая аномалия (ML),
- `PATH_TRAVERSAL` — Path Traversal / LFI,
- `SENSITIVE_FILE_SCAN` — сканирование чувствительных файлов,
- `INVALID_METHOD` — нетипичный HTTP‑метод.

Для каждого типа задана:

- `severity` (1–5) — уровень критичности;
- текстовое `description`.

#### 3.5. `DetectedAnomaly`

Конкретное срабатывание системы анализа.

Основные поля:

- `log_entry` — ссылка на запись лога;
- `anomaly_type` — ссылка на `AnomalyType`;
- `analysis_session` — к какой сессии относится;
- `detection_method` — один из:
  - `ml` — чисто ML (Isolation Forest),
  - `signature` — чисто сигнатурное срабатывание,
  - `hybrid` — одновременно ML + сигнатура;
- `confidence_score` — нормированная уверенность модели (0–1);
- `model_score` — сырое значение `score_samples` от IsolationForest;
- **`explanation`** — человекочитаемое объяснение (ключевое поле для НИР);
- `is_false_positive` — ручная пометка «ложное срабатывание».

#### 3.6. `Alert`

Уведомление для пользователя о важной / критической аномалии.

- `anomaly` — ссылка на `DetectedAnomaly`;
- `recipient` — пользователь, кому назначен алерт;
- `status` — `new`, `in_progress`, `resolved`;
- `message` — человекочитаемое описание (часто включает `explanation`).

#### 3.7. `Report`

Сущность для агрегированных отчётов.

- `summary` — JSON со статистикой по аномалиям;
- `pdf_path` — путь к сгенерированному PDF.

---

### 4. Извлечение признаков и сигнатурный анализ (`services/features.py`)

Модуль `features.py` выполняет две роли:

1. **Извлечение числовых признаков для ML**:
   - `uri_length` — длина URI;
   - `uri_entropy` — энтропия (случайность) URI (Шеннон);
   - `special_char_count` — количество спецсимволов (`?&=%<>"'\\;()[]`);
   - `ip_request_count` — сколько записей с этим IP уже есть в БД (частотный признак);
   - `user_agent_len`, `user_agent` — длина и усечённое значение User-Agent.

2. **Сигнатурный анализ (signature-based)**:
   - `has_sqli_signature` — SQL‑инъекция (`UNION SELECT`, `OR 1=1`, `--`, `EXEC` и др.);
   - `has_xss_signature` — XSS (`<script`, `onerror=`, `javascript:`, `alert(`);
   - `has_path_traversal_signature` — Path Traversal / LFI (`../`, `/etc/passwd`, `/etc/shadow`, `\windows\system32`, `/proc/self/environ`);
   - `has_sensitive_file_scan_signature` — доступ к `.env`, `.git`, `/wp-admin`, `/phpmyadmin`, `backup.sql`, `config.php`, `/admin` и т.п.;
   - `has_invalid_method` — HTTP‑методы, не входящие в «белый список» (`GET`, `POST`, `HEAD`, `OPTIONS`, `PUT`, `PATCH`, `DELETE`);
   - `has_any_signature` — общий флаг наличия хотя бы одного из вышеуказанных срабатываний.

Результатом работы модуля является словарь `features`, который записывается в поле `LogEntry.features` и используется как для ML, так и для принятия решений в API.

---

### 5. Парсинг логов (`services/parser.py`)

Модуль `parser.py` отвечает за разбор строк access.log.

- Используется класс **`NginxAccessLogParser`**:
  - Поддерживает формат **Nginx combined** и совместимый **Apache combined**:
    ```text
    127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
    ```
  - `parse_line(line)`:
    - разбор IP, времени, метода, URI, статуса, User-Agent;
    - возвращает `ParsedLogLine` или `None` (если строка некорректна).
  - `create_log_entry(parsed, web_server, analysis_session)`:
    - вызывает `extract_features_from_parsed(...)` из `features.py`;
    - создаёт и сохраняет `LogEntry` с заполненным полем `features`.

Таким образом, парсер — это мост между **сырой строкой лога** и нормализованной моделью `LogEntry`.

---

### 6. ML‑движок (`services/ml_engine.py`)

Модуль `ml_engine.py` реализует обёртку над **Isolation Forest**.

Основные элементы:

- `FEATURE_ORDER` — список признаков, которые подаются в модель (в фиксированном порядке).
- Класс **`IsolationForestEngine`**:
  - `__init__`:
    - определяет путь к файлу модели (`MEDIA_ROOT/models/isolation_forest.pkl`);
    - настраивает параметры (`contamination`, `random_state`).
  - `fit(feature_dicts)`:
    - принимает набор словарей признаков;
    - строит матрицу признаков;
    - обучает `IsolationForest` и сохраняет модель на диск через `joblib`.
  - `predict(features)`:
    - преобразует признаки в вектор;
    - делает предсказание:
      - `score_samples` — сырая оценка аномальности;
      - `decision_function` — >0 норма, <0 аномалия;
      - `confidence_score` — нормированный показатель уверенности в [0, 1];
    - формирует объект `AnomalyPrediction` с полями:
      - `is_anomaly`,
      - `confidence_score`,
      - `raw_score`,
      - `explanation`.
    - если модель **ещё не обучена**:
      - перехватывает `NotFittedError`,
      - возвращает `confidence_score = 0` и объяснение, что пока используется только сигнатурный анализ.
  - `_build_explanation(...)`:
    - формирует текст на русском, объединяющий:
      - статистические признаки (длина URI, энтропия, спецсимволы, частота IP);
      - наличие сигнатур (`SQLI`, `XSS`, `PATH_TRAVERSAL`, `SENSITIVE_FILE_SCAN`, `INVALID_METHOD`).

Это ядро **ML‑аналитики и интерпретируемости**.

---

### 7. REST API (`views.py`, `serializers.py`, `urls.py`)

#### 7.1. Загрузка логов — `LogUploadView`

Эндпоинт:  
`POST /api/logs/upload/`

Особенности:

- Доступен только администраторам (`IsAdminUser`).
- Поддерживает два режима:
  1. `multipart/form-data` с полем `file` (классический upload).
  2. бинарное тело запроса (raw body / `application/octet-stream` или `text/plain`),
     удобно для Postman → Body → binary.
- Опциональный `web_server_id` можно передать:
  - в multipart (через `LogUploadSerializer`),
  - либо в query‑параметре (`?web_server_id=1`) для бинарного тела.

Пайплайн внутри метода `post`:

1. Читается файл/тело запроса, создаётся `AnalysisSession`.
2. Текст разбивается на строки.
3. Для каждой строки:
   - парсинг через `NginxAccessLogParser.parse_line`;
   - создание `LogEntry` с признаками;
   - вызов `IsolationForestEngine.predict(features)`;
   - анализ флагов в `features`:
     - `has_sqli_signature`,
     - `has_xss_signature`,
     - `has_path_traversal_signature`,
     - `has_sensitive_file_scan_signature`,
     - `has_invalid_method`,
     - а также флаг ML‑аномалии (`confidence_score` выше порога).
   - при срабатывании:
     - создаётся `DetectedAnomaly` c:
       - `detection_method` (`ml`, `signature`, `hybrid`),
       - ссылкой на соответствующий `AnomalyType`,
       - `confidence_score`, `model_score`, `explanation`;
     - при высокой тяжести создаётся `Alert`.
4. В конце сессия обновляется по количеству логов и аномалий.
5. Клиент получает JSON:
   ```json
   {
     "session_id": ...,
     "logs_processed": ...,
     "anomalies_detected": ...
   }
   ```

#### 7.2. Остальные ViewSet’ы

- `DetectedAnomalyViewSet`:
  - `GET /api/anomalies/`, `GET /api/anomalies/{id}/`
  - фильтры: по IP, коду аномалии, методу детекции, статус‑коду и т.п.
  - в каждом объекте отдается `explanation`.
- `AlertViewSet`:
  - `GET /api/alerts/` + `PATCH` для смены статуса;
  - не‑админам показываются только их алерты.
- `AnalysisSessionViewSet`:
  - история запусков: `GET /api/sessions/`.
- `LogEntryViewSet`:
  - просмотр нормализованных логов: `GET /api/log-entries/`.
- `StatsView`:
  - `GET /api/stats/` — агрегированная статистика:
    - общее число логов и аномалий;
    - число новых алертов;
    - распределение аномалий по методам (`ml/signature/hybrid`);
    - распределение по типам (`SQLI`, `XSS`, `PATH_TRAVERSAL` и т.д.).

---

### 8. Администрирование и служебные команды

- `admin.py`:
  - регистрирует все модели в Django Admin;
  - настраивает списки, фильтры, поиск;
  - позволяет помечать `is_false_positive`, просматривать логи, алерты и сессии.
- `management/commands/train_model.py`:
  - команда:
    ```bash
    python manage.py train_model --min-samples 100 --contamination 0.05
    ```
  - обучает Isolation Forest на накопившихся признаках и сохраняет модель.

---

### 9. Инфраструктура

- **`settings.py`**:
  - база: SQLite (`BASE_DIR / "db" / "db.sqlite3"`);
  - `MEDIA_ROOT`: `BASE_DIR / "media"` (там же лежит модель ML);
  - DRF + drf-spectacular (Swagger по `/api/schema/`);
  - базовая настройка CORS, логирования.
- **`Dockerfile`**:
  - образ на `python:3.10-slim`;
  - установка зависимостей из `requirements.txt`;
  - `CMD`: миграции + запуск `runserver`.
- **`docker-compose.yml`**:
  - один сервис `web`;
  - volume’ы:
    - `db_data` → `/app/db`,
    - `media_data` → `/app/media`.

Таким образом, проект удовлетворяет требованиям НИР:
- лёгкая развёртка (SQLite, один контейнер),
- модульность (отдельные модули parsers / features / ml_engine / api),
- гибридный анализ (сигнатуры + ML),
- прозрачность решений (поле `explanation` в API).

