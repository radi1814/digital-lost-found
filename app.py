# app.py
from models import db, User, Item, Notification
import os
from datetime import datetime
import traceback
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
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
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB
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


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
                             DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

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
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if not user:
                flash('No account found with that email.', 'danger')
                return render_template('login.html', form=form)

            if user.check_password(form.password.data):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password.', 'danger')
        except Exception as e:
            # Print traceback in console
            traceback.print_exc()
            flash('An error occurred during login. Please try again.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have logged out.', 'info')
    return redirect(url_for('login'))

# ----------------------
# PASSWORD RESET
# ----------------------


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash('Please reset your password below.', 'info')
            return redirect(url_for('reset_password', user_id=user.id))
        else:
            flash('No account found with that email.', 'danger')
    return render_template('forgot_password.html', form=form)


@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    form = ResetPasswordForm()
    user = User.query.get_or_404(user_id)
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Your password has been updated. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

# ----------------------
# DASHBOARD & ITEMS
# ----------------------


@app.route('/dashboard')
@login_required
def dashboard():
    # Only items reported by the current user
    my_items = Item.query.filter_by(user_id=current_user.id).order_by(
        Item.created_at.desc()).limit(5).all()

    notifications = Notification.query.filter_by(
        receiver_id=current_user.id, is_read=False
    ).order_by(Notification.created_at.desc()).limit(5).all()

    return render_template('dashboard.html', all_items=my_items, notifications=notifications)


@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_item():
    form = ItemForm()
    if form.validate_on_submit():
        filename = None
        if form.photo.data:
            filename = secure_filename(form.photo.data.filename)
            form.photo.data.save(os.path.join(
                app.config['UPLOAD_FOLDER'], filename))
        item = Item(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            status=form.status.data,
            location=form.location.data,
            photo=filename,
            user_id=current_user.id
        )
        db.session.add(item)
        db.session.commit()
        flash('Item reported successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('report_item.html', form=form)


@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.filter_by(
        id=item_id, user_id=current_user.id).first_or_404()
    form = ItemForm(obj=item)

    if form.validate_on_submit():
        item.title = form.title.data
        item.description = form.description.data
        item.category = form.category.data
        item.status = form.status.data
        item.location = form.location.data

        # If user uploads new photo, replace the old one
        if form.photo.data:
            filename = secure_filename(form.photo.data.filename)
            form.photo.data.save(os.path.join(
                app.config['UPLOAD_FOLDER'], filename))
            # delete old photo if exists
            if item.photo:
                old_path = os.path.join(
                    app.config['UPLOAD_FOLDER'], item.photo)
                if os.path.exists(old_path):
                    os.remove(old_path)
            item.photo = filename

        db.session.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_item.html', form=form, item=item)


@app.route('/lost')
def lost_items():
    items = Item.query.filter_by(status='Lost').order_by(
        Item.created_at.desc()).all()
    return render_template('lost.html', items=items)


@app.route('/found')
def found_items():
    items = Item.query.filter_by(status='Found').order_by(
        Item.created_at.desc()).all()
    return render_template('found.html', items=items)


@app.route('/item/<int:item_id>')
def item_details(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item_details.html', item=item)


@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    # Find the item belonging to the current user
    item = Item.query.filter_by(
        id=item_id, user_id=current_user.id).first_or_404()

    # Delete the photo file if it exists
    if item.photo:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], item.photo)
        if os.path.exists(photo_path):
            os.remove(photo_path)

    # Delete the item from the database
    db.session.delete(item)
    db.session.commit()

    flash('Item deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/notifications')
@login_required
def notifications():
    notes = Notification.query.filter_by(
        receiver_id=current_user.id
    ).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=notes)

# ----------------------
# ERROR HANDLERS
# ----------------------


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    traceback.print_exc()
    return render_template('500.html'), 500


# ----------------------
# RUN APP
# ----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
