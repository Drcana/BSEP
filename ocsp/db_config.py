from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()

class Record(db.Model):
    sn = db.Column(db.String(48), primary_key=True)
    cert = db.Column(db.Binary, nullable=False)
    issuer_sn = db.Column(db.String(48), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    reason = db.Column(db.String(20), nullable=True)

    def save(self):
        db.session.add(self)
        db.session.commit()


migrate = Migrate()