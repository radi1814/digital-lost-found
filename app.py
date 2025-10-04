# app.py
from models import db, User, Item, Notification
import os
from datetime import datetime
import traceback
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_wtf.file import FileField, FileAllowed
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
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ----------------------
# DATABASE AND MODELS
# ----------------------

db.init_app(app)

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

# ----------------------
# AUTHENTICATION
# ----------------------


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
        flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# ----------------------
# DASHBOARD
# ----------------------


@app.route('/dashboard')
@login_required
def dashboard():
    all_items = Item.query.filter_by(
        user_id=current_user.id).order_by(Item.created_at.desc()).all()
    notifications = Notification.query.filter_by(receiver_id=current_user.id).order_by(
        Notification.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', all_items=all_items, notifications=notifications)

# ----------------------
# REPORT ITEM
# ----------------------


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

# ----------------------
# LOST AND FOUND
# ----------------------


@app.route('/lost')
def lost_items():
    items = Item.query.filter_by(status='Lost').order_by(
        Item.created_at.desc()).all()
    return render_template('lost.html', items=items, status='Lost')


@app.route('/found')
def found_items():
    items = Item.query.filter_by(status='Found').order_by(
        Item.created_at.desc()).all()
    return render_template('found.html', items=items, status='Found')


@app.route('/item/<int:item_id>')
def item_details(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item_details.html', item=item)

# ----------------------
# NOTIFICATIONS
# ----------------------


@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(
        receiver_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notifications)


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

# ======================
# ERROR HANDLERS
# ======================


@app.errorhandler(404)
def page_not_found(e):
    try:
        return render_template('404.html'), 404
    except:
        return "404 - Page Not Found", 404


@app.errorhandler(500)
def internal_error(e):
    print("---- 500 ERROR ----")
    print(traceback.format_exc())
    try:
        return render_template('500.html'), 500
    except:
        return "500 - Internal Server Error", 500


# ======================
# RUN APP
# ======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
