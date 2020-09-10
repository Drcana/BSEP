from ca.extensions import db

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
