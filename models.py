import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class ProtectedCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(100), unique=True, index=True, nullable=False, default=lambda: str(uuid.uuid4()))
    code = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref=db.backref('codes', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    create_ip = db.Column(db.String(64))

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_id = db.Column(db.Integer, db.ForeignKey('protected_code.id'), nullable=False)
    path = db.Column(db.String(16), nullable=False)  # "code" or "raw"
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    code = db.relationship('ProtectedCode', backref=db.backref('access_logs', lazy=True))
