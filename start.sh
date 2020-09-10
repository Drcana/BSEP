#!/usr/bin/env bash
source venv/bin/activate
cd ./ca
flask db init
flask db migrate
flask db upgrade
