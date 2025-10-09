FROM python:3.11-slim

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV YARA_RULES_URL="https://github.com/BlackSnufkin/LitterBox/archive/refs/heads/main.zip"
ENV YARA_RULES_DIR="/app/api/analysis/services/yara_rules/rules"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libmagic1 \
    libyara-dev \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy project
COPY backend/ .
COPY --chown=www-data:www-data dropper_core/ /app/dropper_core/

# Collect static files
RUN python manage.py collectstatic --noinput

# Create and switch to a non-root user
RUN useradd -m myuser && chown -R myuser:myuser /app
USER myuser

# Gunicorn configuration
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "backend.wsgi:application"]
