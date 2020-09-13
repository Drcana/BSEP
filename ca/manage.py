from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./ca/db-ca.db'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)
class Record(db.Model):
    cert_pk = db.Column(db.String(48), primary_key=True)
    created_at = db.Column(
        db.DateTime(timezone=True), server_default=db.func.now()
    )
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    common_name = db.Column(db.String(256), name='commonName', nullable=False)
    cert = db.Column(db.Binary, nullable=False)

    def save(self):
        db.session.add(self)
        db.session.commit()

if __name__ == '__main__':
    manager.run()