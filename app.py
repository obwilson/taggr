from flask import Flask, render_template, redirect, flash, request, session
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask_uploads import UploadSet, configure_uploads
from wtforms import StringField, SubmitField, EmailField, PasswordField, FileField, SelectField
from wtforms.validators import DataRequired, Length, Optional
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from flask_login import (
    login_user,
    LoginManager,
    login_required,
    logout_user,
    current_user,
)
from sqlalchemy.orm.attributes import flag_modified
from PIL import Image
from datetime import datetime
import os
import json

app = Flask(__name__)

from models import Users, Photos
from db import db, db_init

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["UPLOADED_PHOTOS_DEST"] = "static/uploads"
app.config["SECRET_KEY"] = "photo"

ALLOWED_FILES = ["png", "jpg", "jpeg"]

photos = UploadSet("photos", ALLOWED_FILES)
configure_uploads(app, photos)

os.makedirs(app.config["UPLOADED_PHOTOS_DEST"], exist_ok=True)

# User Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


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
                message="Password must be shorter than 20 characters.",
            ),
        ],
    )
    confirm_password = PasswordField(
        label="Confirm Password",
        validators=[
            DataRequired(),
            Length(
                min=8,
                message="Password must be longer than 8 characters.",
            ),
            Length(
                max=20,
                message="Password must be shorter than 20 characters.",
            ),
        ],
    )
    submit = SubmitField("Sign Up")


# Log In Form Class
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
    submit = SubmitField("Log In")


class UpdateAccountForm(FlaskForm):
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
        label="New Password",
        validators=[
            Optional(),
            Length(
                min=8,
                message="Password must be longer than 8 characters.",
            ),
            Length(
                max=20,
                message="Password must be shorter than 20 characters.",
            ),
        ],
    )
    confirm_password = PasswordField(
        label="Confirm Password",
        validators=[
            Optional(),
            Length(
                min=8,
                message="Password must be longer than 8 characters.",
            ),
            Length(
                max=20,
                message="Password must be shorter than 20 characters.",
            ),
        ],
    )
    submit = SubmitField("Update Information")


class PhotoForm(FlaskForm):
    photo = FileField(
        "Upload Photo",
        validators=[
            FileAllowed(photos),
            FileRequired(),
        ],
    )
    submit = SubmitField("Upload Photo")


class TagForm(FlaskForm):
    tag_name = StringField(
        label="Tag Name",
        validators=[
            DataRequired(),
            Length(min=1, max=20),
        ],
    )
    tag_colour = SelectField(
        label="Tag Colour",
        validators=[
            DataRequired(),
        ],
        choices=[
            ("danger", "Red"),
            ("warning", "Yellow"),
            ("success", "Green"),
            ("primary", "Blue"),
            ("info", "Light Blue"),
            ("light", "White"),
            ("secondary", "Grey"),
            ("dark", "Black"),
        ]
    )
    submit = SubmitField("Create")


# Index Page
@app.route("/")
def index():
    if current_user is None:
        return redirect("/signup")
    else:
        return redirect("/home")


# Sign Up Page
@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        if form.password.data == form.confirm_password.data:
            user = Users.query.filter_by(email=form.email.data).first()
            if user is None:
                password_hash = generate_password_hash(
                    form.password.data, "pbkdf2:sha256"
                )

                user = Users(
                    username=form.username.data,
                    email=form.email.data,
                    password_hash=password_hash,
                )

                db.session.add(user)
                db.session.commit()

                login_user(user)
                return redirect("/home")
        else:
            flash("Passwords do not match.")

    return render_template("signup.html", form=form)


# Log In Page
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if user.verify_password(form.password.data):
                login_user(user)
                flash("Successfully logged in!")
                return redirect("/home")
            else:
                flash("Password is incorrect. Please try again.")
        else:
            flash("User not found. Please try again.")

    return render_template("login.html", form=form)


# Logout User
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Successfully Logged Out.")
    return redirect("/login")


@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    if Photos.query.filter_by(user=current_user.id).count() > 0:
        has_photos = True
    else:
        has_photos = False

    photos = []

    form = TagForm()

    img_filter = None
    sort_by = "Newest"

    if request.method == "POST":
        filter_button = request.form.get('filter_button')
        sort_button = request.form.get('sort_button')

        if form.tag_name.data is not None:
            tag = [form.tag_name.data, form.tag_colour.data]
        else:
            tag = None
        user_tags = current_user.tags

        if filter_button == "None":
            session['filter_button'] = None
        elif filter_button:
            session['filter_button'] = filter_button
        else:
            filter_button = session.get('filter_button')

        if sort_button:
            session['sort_button'] = sort_button
        else:
            sort_button = session.get('sort_button')

        if session.get('filter_button'):
            img_filter = json.loads(session['filter_button'].replace("'", "\""))

        sort_by = session.get('sort_button', "Newest")

        if tag is not None:
            if user_tags:
                if tag in user_tags:
                    flash("Tag name/colour already exists. Please try again.")
                else:
                    user_tags.append(tag)
                    current_user.tags = user_tags
                    flag_modified(current_user, "tags")
                    db.session.commit()
                    flash("Tag created.")
            else:
                user_tags.append(tag)
                current_user.tags = user_tags
                flag_modified(current_user, "tags")
                db.session.commit()
                flash("Tag created.")
    else:
        if session.get('filter_button'):
            img_filter = json.loads(session['filter_button'].replace("'", "\""))
        sort_by = session.get('sort_button', "Newest")

    for photo in Photos.query.filter_by(user=current_user.id):
        if img_filter:
            if img_filter in photo.tags:
                photos.append(photo)
        else:
            photos.append(photo)

    if sort_by == "Newest":
        photos.sort(reverse=True, key=lambda x: x.date_added)
    elif sort_by == "Oldest":
        photos.sort(key=lambda x: x.date_added)

    return render_template("home.html", photos=photos, tags=current_user.tags, form=form, img_filter=img_filter, sort_by=sort_by, has_photos=has_photos)



@app.route("/update-user", methods=["GET", "POST"])
@login_required
def update_user():
    form = UpdateAccountForm()

    if form.validate_on_submit():
        if form.username.data != current_user.username:
            if Users.query.filter_by(username=form.username.data).first():
                flash("Username already exists.")
            else:
                current_user.username = form.username.data

        if form.email.data != current_user.email:
            if Users.query.filter_by(email=form.email.data).first():
                flash("Email already exists.")
            else:
                current_user.email = form.email.data

        if form.password.data:
            if form.password.data == form.confirm_password.data:
                password_hash = generate_password_hash(
                    form.password.data, "pbkdf2:sha256"
                )

                current_user.password_hash = password_hash
            else:
                flash("Passwords do not match.")

        try:
            db.session.commit()
            flash("Account info updated.")
            return render_template("update_user.html", form=form)
        except:
            flash("An error has occured. Please try again.")
            return render_template("update_user.html", form=form)

    return render_template("update_user.html", form=form)


@app.route("/delete-user")
@login_required
def delete_user():
    user_to_delete = current_user
    photos = Photos.query.filter_by(user=user_to_delete.id)

    try:
        if photos:
            for photo in photos:
                os.remove(photo.file_path)
                db.session.delete(photo)
                print(f"Deleted {photo.file_path} from user {photo.user}")

        db.session.delete(user_to_delete)
        db.session.commit()
        flash("Account deleted successfully.")
        return redirect("/")
    except:
        flash("An error has occured. Please try again.")
        return redirect("/update-user")


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    form = PhotoForm()

    if form.validate_on_submit():
        photo = form.photo.data

        try:
            Image.open(photo).verify()
            photo.seek(0)
        except:
            flash(
                "The uploaded image is either invalid or contains corrupted data. Please try again with a different file."
            )

            return redirect("/upload")

        if photo:
            folder_path = os.path.join(
                app.config["UPLOADED_PHOTOS_DEST"],
                str(current_user.id),
            )
            os.makedirs(folder_path, exist_ok=True)

            file_name = secure_filename(f"{datetime.now().strftime("%d-%m-%Y %H:%M:%S")}_{photo.filename}")
            file_path = os.path.join(
                folder_path,
                file_name,
            )

            photo.save(file_path)

            new_photo = Photos(user=current_user.id, file_path=file_path)
            db.session.add(new_photo)
            db.session.commit()

            flash(f"{photo.filename} uploaded successfully.")

            return redirect("/upload")

    return render_template("upload.html", form=form)

@app.route("/add_tag/<photo_id>")
@login_required
def add_tag(photo_id):
    tag_name = request.args.get('tag_name')
    tag_colour = request.args.get('tag_colour')

    photo = Photos.query.get_or_404(photo_id)

    tags = []

    for tag in photo.tags:
        tags.append(tag)

    if photo:
        if tag_name and tag_colour:
            tag = [tag_name, tag_colour]
            if tag in tags:
                flash(f"Photo is already tagged with {tag_name}")
            else:
                tags.append(tag)
                photo.tags = tags

            db.session.commit()
        else:
            flash("Information missing. Please try again.")

    return redirect("/home")

@app.route("/remove_tag/<photo_id>")
def remove_tag(photo_id):
    tag_name = request.args.get('tag_name')
    tag_colour = request.args.get('tag_colour')

    photo = Photos.query.get_or_404(photo_id)

    tags = []

    for tag in photo.tags:
        tags.append(tag)

    if photo:
        tag = [tag_name, tag_colour]

        if tag in tags:
            tags.remove(tag)
            print(f"Removed {tag}")

            photo.tags = tags
            db.session.commit()

    return redirect("/home")


if __name__ == "__main__":
    db_init(app)
    app.run(debug=True)
