import logging
import os

import pem
from cryptography.hazmat.backends import default_backend
from flask import Flask
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography.x509 import (
    load_pem_x509_certificate,
    Certificate
)

from ocsp.db_config import db, migrate
from ocsp.resources import router


def create_app():
    app = Flask(__name__)
    configure(app)
    app.register_blueprint(router)
    return app


def configure(app):
    app.config.from_pyfile('config.py')
    app.config.from_pyfile(os.environ.get('CONFIG_FILE', ''), silent=True)
    register_extensions(app)
    print(app.config)

    pem_responder_cert = pem.parse_file(app.config['CERT_PATH'])[0]
    pem_responder_key = pem.parse_file(app.config['KEY_PATH'])[0]

    app.config['CERT'] = load_pem_x509_certificate(
        pem_responder_cert.as_bytes(),
        backend=default_backend()
    )
    app.config['KEY'] = load_pem_private_key(
        pem_responder_key.as_bytes(),
        password=None,
        backend=default_backend()
    )



    # issuers = {}
    # issuers_bundle = pem.parse_file(app.config['ISSUERS_PATH'])
    # for issuer in issuers_bundle:
    #     cert: Certificate = load_pem_x509_certificate(
    #         data=issuer.as_bytes(),
    #         backend=default_backend()
    #     )
    #     issuers[str(cert.serial_number)] = cert

    # app.config['ISSUERS'] = issuers

def register_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)


app = create_app()

