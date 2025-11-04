import os
from flask import (Flask, render_template, request, redirect, 
                   url_for, flash, session)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_bcrypt import Bcrypt
from flask_login import (LoginManager, UserMixin, login_user, 
                       logout_user, login_required, current_user)

# --- App Configuration ---
app = Flask(__name__)
# SECRET_KEY is required for CSRF protection (Task 1 & 3)
app.config['SECRET_KEY'] = 'a-very-strong-random-secret-key-that-no-one-can-guess'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'

# --- Library Initialization ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app) # For Task 5: Password Hashing
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redirect to login if user is not authenticated
login_manager.login_message_category = 'info'


# --- Models (Database Structure) ---
# We implement UserMixin for Flask-Login (Task 3: Session Management)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Task 5: Store a HASH, not the password
    password_hash = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"

# Required by Flask-Login to manage user sessions
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- Forms (Task 1: Input Validation & Task 3: CSRF) ---
class RegistrationForm(FlaskForm):
    name = StringField('Name', 
                       validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EditUserForm(FlaskForm):
    name = StringField('Name', 
                       validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Update User')


# --- Routes (Application Logic) ---

@app.route('/')
@app.route('/index')
def index():
    users = User.query.all()
    return render_template('index.html', users=users, title="User List")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    # This single line handles Task 1 (Validation) and Task 3 (CSRF)
    if form.validate_on_submit():
        # Task 5: Hash the password
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        # Task 2: Parameterized query is handled by the ORM
        new_user = User(name=form.name.data, 
                        email=form.email.data, 
                        password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Task 5: Check the hashed password
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            # Task 3: Create a secure user session
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
            
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user() # Task 3: Securely clear the session
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required # Protect this route
def edit(id):
    user = User.query.get_or_404(id)
    form = EditUserForm()
    
    if form.validate_on_submit(): # Handles POST, validation, and CSRF
        user.name = form.name.data
        user.email = form.email.data
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('index'))
    elif request.method == 'GET':
        # Pre-populate the form with current data
        form.name.data = user.name
        form.email.data = user.email
        
    return render_template('edit.html', title='Edit User', form=form, user=user)

@app.route('/delete/<int:id>')
@login_required # Protect this route
def delete(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('index'))


# --- Task 4: Secure Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    # Prevents leaking info about valid/invalid URLs
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # Prevents leaking sensitive debug info (file paths, code, etc.)
    return render_template('500.html'), 500


# --- Main Runner ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates the new tasks.db if it doesn't exist
    # Task 4: Set debug=False for production/submission
    app.run(debug=False)