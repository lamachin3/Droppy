#!/bin/sh
set -e
cd /app

echo "Running Django setup commands..."
python3 manage.py download_yara_rules || echo "Skipping yara rules"

echo "Starting Django server..."
python manage.py runserver 0.0.0.0:8000
