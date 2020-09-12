#!/usr/bin/env bash
source venv/bin/activate

export FLASK_APP=./ca/app.py
flask run --host 0.0.0.0 --port 5000

