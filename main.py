from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo

app = Flask(__name__)
app.config['SECRET_KEY'] = "photo"

# Sign Up Form Class
class SignUpForm(FlaskForm):
    username = StringField(
        label="Username",
        validators=[
            DataRequired(),
            Length(min=3, max=12),
        ],
    )
    email = EmailField(
        label="Email",
        validators=[
            DataRequired(),
        ],
    )
    password = PasswordField(
        label="Password",
        validators=[
            DataRequired(),
            Length(
                min=8,
                message="Password must be longer than 8 characters.",
            ),
            Length(
                max=20,
                message="Password must be shorter than 30 characters.",
            ),
            EqualTo(
                "confirm_password",
                message="Passwords don't match.",
            ),
        ],
    )
    confirm_password = PasswordField(
        label="Confirm Password",
        validators=[
            DataRequired(),
            EqualTo(
                "password",
                message="Passwords don't match.",
            ),
        ],
    )
    submit = SubmitField("Sign Up")

# Login Form Class
class LoginForm(FlaskForm):
    username = StringField(
        label="Username",
        validators=[
            DataRequired(),
            Length(min=3, max=12),
        ],
    )
    password = PasswordField(
        label="Password",
        validators=[
            DataRequired(),
        ],
    )
    submit = SubmitField("Sign Up")

# Index Page
@app.route('/')
def index():
    return render_template("index.html")

# Sign Up Page
@app.route('/signup')
def signup():
    form = SignUpForm()

    return render_template("signup.html", form=form)

# Log In Page
@app.route('/login')
def login():
    form = LoginForm()

    return render_template("login.html", form=form)

if __name__ == "__main__":
    app.run(debug=True)