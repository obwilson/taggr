from flask import Flask, render_template, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash
from flask_login import login_user, LoginManager, login_required, logout_user, current_user

app = Flask(__name__)

from models import Users
from db import db, db_init

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'photo'

# User Login
login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Sign Up Form Class
class SignUpForm(FlaskForm):
    username = StringField(
        label='Username',
        validators=[
            DataRequired(),
            Length(min=3, max=12),
        ],
    )
    email = EmailField(
        label='Email',
        validators=[
            DataRequired(),
        ],
    )
    password = PasswordField(
        label='Password',
        validators=[
            DataRequired(),
            Length(
                min=8,
                message='Password must be longer than 8 characters.',
            ),
            Length(
                max=20,
                message='Password must be shorter than 20 characters.',
            ),
        ],
    )
    confirm_password = PasswordField(
        label='Confirm Password',
        validators=[
            DataRequired(),
            Length(
                min=8,
                message='Password must be longer than 8 characters.',
            ),
            Length(
                max=20,
                message='Password must be shorter than 20 characters.',
            ),
        ],
    )
    submit = SubmitField('Sign Up')

# Log In Form Class
class LoginForm(FlaskForm):
    username = StringField(
        label='Username',
        validators=[
            DataRequired(),
            Length(min=3, max=12),
        ],
    )
    password = PasswordField(
        label='Password',
        validators=[
            DataRequired(),
        ],
    )
    submit = SubmitField('Log In')

# Index Page
@app.route('/')
def index():
    if current_user is None:
        return redirect("/signup")
    else:
        return redirect("/home")

# Sign Up Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        if form.password.data == form.confirm_password.data:
            user = Users.query.filter_by(email=form.email.data).first()
            if user is None:
                password_hash = generate_password_hash(form.password.data, 'pbkdf2:sha256')

                user = Users(
                    username = form.username.data,
                    email = form.email.data,
                    password_hash = password_hash
                )

                db.session.add(user)
                db.session.commit()

                login_user(user)
                return redirect('/home')
        else:
            flash("Passwords do not match.")

    return render_template('signup.html', form=form)

# Log In Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if user.verify_password(form.password.data):
                login_user(user)
                flash("Successfully logged in!")
                return redirect('/home')
            else:
                flash("Password is incorrect. Please try again.")
        else:
            flash("User not found. Please try again.")

    return render_template('login.html', form=form)

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

if __name__ == '__main__':
    db_init(app)
    app.run(debug=True)