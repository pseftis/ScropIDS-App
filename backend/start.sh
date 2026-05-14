#!/bin/sh
set -eu

echo "Starting Celery Worker..."
celery -A scropids worker --loglevel=info &

echo "Starting Celery Beat..."
celery -A scropids beat --loglevel=info &

echo "Starting Gunicorn Web Server..."
# Render provides the PORT environment variable dynamically
exec gunicorn scropids.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 2 --timeout 120
