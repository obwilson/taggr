from flask import Flask, render_template, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash

app = Flask(__name__)

from models import Users
from db import db, db_init


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'photo'

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
                message='Password must be shorter than 30 characters.',
            ),
            EqualTo('confirm_password', message='Passwords do not match.')
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
                message='Password must be shorter than 30 characters.',
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
    return render_template('index.html')

# Sign Up Page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
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
            flash(f'{user.verify_password(form.password.data)}')
            return redirect('/home')

    return render_template('signup.html', form=form)

# Log In Page
@app.route('/login')
def login():
    form = LoginForm()

    return render_template('login.html', form=form)

@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    db_init(app)
    app.run(debug=True)