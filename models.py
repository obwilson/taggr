from db import db
from datetime import datetime
from werkzeug.security import check_password_hash
from flask_login import UserMixin


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.now())

    # Password hashing
    password_hash = db.Column(db.String(256))

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    

class Photos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer, nullable=False)
    file_path = db.Column(db.String(256), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now())