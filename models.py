"""
This module defines the SQLAlchemy database models for the program. 

Users: Stores information around user accounts, tracked with uploaded UTC time.
Includes a function to verify the user's hashed password against a plain string.

Photos: Stores information around photos, tracked with uploaded UTC time. Stores
the current user ID to reference back to the users model.

15/08/2025
"""

from db import db
from datetime import datetime, UTC
from werkzeug.security import check_password_hash
from flask_login import UserMixin


## Users Database
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(12), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    tags = db.Column(db.JSON, default=[])
    date_added = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

    # Password hashing
    password_hash = db.Column(db.String(256))

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    

## Photos Database
class Photos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer, nullable=False)
    file_path = db.Column(db.String(256), nullable=False)
    tags = db.Column(db.JSON, default=[])
    date_added = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
