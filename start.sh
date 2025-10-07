#!/usr/bin/env bash
set -e
python -m pip install --upgrade pip
pip install -r requirements.txt
# export FLASK_ENV=production
exec gunicorn app:app -b 0.0.0.0:${PORT:-5000} --log-level info
