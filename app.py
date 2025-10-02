from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv

# ----------------------
# LOAD ENVIRONMENT VARIABLES
# ----------------------
load_dotenv()

# ----------------------
# FLASK APP SETUP
# ----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------------
# DATABASE SETUP
# ----------------------
db = SQLAlchemy(app)

# ----------------------
# FLASK-LOGIN SETUP
# ----------------------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ======================
# DATABASE MODELS
# ======================


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    profile_pic = db.Column(db.String(200), default="default.png")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    items = db.relationship("Item", backref="user", lazy=True)
    notifications = db.relationship(
        "Notification", backref="receiver", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Item(db.Model):
    __tablename__ = "items"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    photo = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    receiver_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False)

# ======================
# FLASK-WTF FORMS
# ======================


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=3, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email already exists.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ItemForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    category = SelectField('Category', choices=[(
        'Electronics', 'Electronics'), ('Clothes', 'Clothes'), ('Other', 'Other')])
    status = SelectField('Status', choices=[
                         ('Lost', 'Lost'), ('Found', 'Found')])
    location = StringField('Location', validators=[DataRequired()])
    photo = FileField('Photo', validators=[FileAllowed(
        ['jpg', 'jpeg', 'png'], 'Images only!')])
    submit = SubmitField('Report Item')

# ======================
# ROUTES
# ======================


@app.route('/')
def home():
    return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    items = Item.query.filter_by(user_id=current_user.id).order_by(
        Item.created_at.desc()).all()
    notifications = Notification.query.filter_by(receiver_id=current_user.id).order_by(
        Notification.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', items=items, notifications=notifications)


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    form = ItemForm()
    if form.validate_on_submit():
        photo_filename = None
        if form.photo.data:
            filename = f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{secure_filename(form.photo.data.filename)}"
            form.photo.data.save(os.path.join(
                app.config['UPLOAD_FOLDER'], filename))
            photo_filename = filename

        new_item = Item(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            status=form.status.data,
            location=form.location.data,
            photo=photo_filename,
            user_id=current_user.id
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Item reported successfully!', 'success')
        return redirect(url_for('dashboard'))

    items = Item.query.filter_by(user_id=current_user.id).order_by(
        Item.created_at.desc()).all()
    return render_template('report.html', form=form, items=items)


@app.route('/notifications/mark_read/<int:note_id>', methods=['POST'])
@login_required
def mark_notification_read(note_id):
    note = Notification.query.filter_by(
        id=note_id, receiver_id=current_user.id).first()
    if note:
        note.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 404


@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(
        receiver_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)

# ----------------------
# Filter Items (Lost/Found)
# ----------------------


@app.route('/items/<status>')
@login_required
def filter_items(status):
    if status not in ['Lost', 'Found']:
        flash('Invalid status', 'danger')
        return redirect(url_for('dashboard'))

    items = Item.query.filter_by(status=status).order_by(
        Item.created_at.desc()).all()
    template = 'lost.html' if status == 'Lost' else 'found.html'
    # ✅ pass status
    return render_template(template, items=items, status=status)

# ======================
# ERROR HANDLERS
# ======================


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500


# ======================
# RUN APP
# ======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
