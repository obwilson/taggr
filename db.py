"""
This module creates the SQLAlchemy database and initialises it with the modules
defined in the models file.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def db_init(app):
    db.init_app(app)

    with app.app_context():
        db.create_all()