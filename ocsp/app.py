import os

from flask import Flask

from ocsp.resources import router

def create_app():
    app = Flask(__name__)
    configure(app)
    app.register_blueprint(router)
    return app


def configure(app):
    app.config.from_pyfile('config.py')
    app.config.from_pyfile(os.environ.get('CONFIG_FILE', ''), silent=True)

    print(app.config)

app = create_app()

