FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Устанавливаем только Python-зависимости
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код
COPY . /app/

# Директории для БД и медиа (монтируются как volume)
RUN mkdir -p /app/db /app/media /app/staticfiles

ENV DJANGO_SETTINGS_MODULE=log_analysis.settings

EXPOSE 8000

# Миграции и запуск dev-сервера
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py runserver 0.0.0.0:8000"]