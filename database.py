from models import db
from flask import current_app
from sqlalchemy import text

# ======================
# Helper functions
# ======================


def execute_query(query, params=None):
    """
    Execute a raw SQL SELECT query and return a list of dictionaries.
    """
    with current_app.app_context():
        with db.engine.connect() as conn:
            result = conn.execute(text(query), params or {})
            return result.mappings().all()  # returns dicts instead of tuples


def execute_commit(query, params=None):
    """
    Execute a raw SQL command (INSERT/UPDATE/DELETE) with transaction support.
    """
    with current_app.app_context():
        with db.engine.begin() as conn:  # automatically commits/rolls back
            conn.execute(text(query), params or {})


def fetch_one(query, params=None):
    """
    Execute a SELECT query and return the first row as a dictionary.
    """
    with current_app.app_context():
        with db.engine.connect() as conn:
            result = conn.execute(text(query), params or {})
            return result.mappings().first()
