import os
from io import BytesIO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from cryptography import x509
from flask import Flask
from flask_migrate import Migrate
import pem

from ca.extensions import db, migrate
from ca.resources import router

def create_app():
    app = Flask(__name__)
    CORS(app)
    register_extensions(app)
    register_blueprints(app)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/vlazd/PycharmProjects/bsep_/db/db-ca.db'
    chain = pem.parse_file("./generated_keys/ca_demo/ca_demo.crt")
    app.config['CERT_CHAIN'] = [bytes(str(c), encoding='utf-8') for c in chain]

    app.config['CERT_PEM'] = str(chain[0])
    cert = BytesIO(bytes(str(chain[0]), encoding='utf-8'))
    app.config['CERT'] = x509.load_pem_x509_certificate(
        data=cert.read(),
        backend=default_backend()
    )

    with open("./generated_keys/ca_demo/ca_demo.key", 'rb') as f:
        app.config['KEY'] = load_pem_private_key(
            data=f.read(),
            password=None,
            backend=default_backend()
        )


    return app


def register_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)


def register_blueprints(app):
    app.register_blueprint(router)


app = create_app()
app.run()
