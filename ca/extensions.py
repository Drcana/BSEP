from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_oidc import OpenIDConnect

db = SQLAlchemy()
migrate = Migrate()
oidc = OpenIDConnect()

