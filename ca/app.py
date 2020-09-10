import os
from io import BytesIO

from flask_sqlalchemy import SQLAlchemy
from cryptography import x509
from flask import Flask
from flask_migrate import Migrate

from ca.extensions import db, migrate
from ca.resources import router

from OpenSSL import SSL

context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_privatekey_file('../key.pem')
context.use_certificate_file('../cert.pem')



def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://///Users/vlazd/PycharmProjects/bsep_/db/db-ca.db'

    configure(app)
    register_extensions(app)
    register_blueprints(app)
    return app

def configure(app):
    pass

def register_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)

def register_blueprints(app):
    app.register_blueprint(router)

app = create_app()

app.run(host='127.0.0.1', debug=True, ssl_context=context)
