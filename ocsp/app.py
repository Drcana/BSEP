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
from flask_sqlalchemy import SQLAlchemy

from ocsp.db_config import migrate, db, Record
from ocsp.resources import router


def create_app():
    app = Flask(__name__)
    configure(app)
    app.register_blueprint(router)
    return app


# OCSP_DB_ADDRESS=localhost
# OCSP_DB_PORT=3306
# OCSP_DB_NAME=db_ocsp
# OCSP_DB_USER=postgres
# OCSP_DB_PASSWORD=root
# OCSP_DB_ROOT_PASSWORD=root
#
# OCSP_KEY_PATH=generated_keys/r1-ca-1/r1-ca-1.key
# OCSP_CERT_PATH=generated_keys/r1-ca-1/r1-ca-1.crt
# OCSP_ISSUERS_PATH=generated_keys/issuers-bundle.pem
#


def configure(app):
    POSTGRES = {
        'user': 'postgres',
        'pw': 'root',
        'db': 'db_ocsp',
        'host': 'localhost',
        'port': '5432',
    }
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:\
    %(pw)s@%(host)s:%(port)s/%(db)s' % POSTGRES
    register_extensions(app)

    app.config.from_pyfile('config.py')
    app.config.from_pyfile

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

