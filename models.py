from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# initialize db (imported in app.py later)
db = SQLAlchemy()

# ======================
# User Model
# ======================


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # can store logo/image path
    profile_pic = db.Column(db.String(200), default="default.png")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    items = db.relationship("Item", backref="user", lazy=True)
    notifications = db.relationship(
        "Notification", backref="receiver", lazy=True)

    # Password helpers
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# ======================
# Item Model (Lost/Found reports)
# ======================


class Item(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(10), nullable=False)  # "Lost" or "Found"
    location = db.Column(db.String(150), nullable=False)
    photo = db.Column(db.String(200))  # path/URL to image
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign key to link with user
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

# ======================
# Notification Model
# ======================


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign key → who receives this notification
    receiver_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)
