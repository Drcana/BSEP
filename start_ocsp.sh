#!/usr/bin/env bash
export FLASK_APP=./ocsp/app.py
flask run --host 0.0.0.0 --port 5001
