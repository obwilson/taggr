"""
Taggr: A web app for uploading, tagging, and sorting photos.

The program includes a simple to use tag system that the
user can use to filter by in order to find specific categories of photo. The app
integrates with multiple HTML documents for rendering the user interface.

15/08/2025
"""

import os
import json
from datetime import datetime

from flask import Flask, render_template, redirect, flash, request, session
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
from flask_uploads import UploadSet, configure_uploads
from wtforms import (
    StringField,
    SubmitField,
    EmailField,
    PasswordField,
    SelectField,
)
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

from models import Users, Photos
from db import db, db_init

app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["UPLOADED_PHOTOS_DEST"] = "static/uploads"
app.config["SECRET_KEY"] = "photo"

ALLOWED_FILES = ["png", "jpg", "jpeg"]

photos = UploadSet("photos", ALLOWED_FILES)
configure_uploads(app, photos)

os.makedirs(app.config["UPLOADED_PHOTOS_DEST"], exist_ok=True)

## User Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


## Load logged in user from database
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


## Sign Up Form Class
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


## Log In Form Class
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


## Update Account Form
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


## Photo Form
class PhotoForm(FlaskForm):
    photo = FileField(
        "Upload Photo",
        validators=[
            FileAllowed(photos),
            FileRequired(),
        ],
    )
    submit = SubmitField("Upload Photo")


## Create Tag Form
class CreateTagForm(FlaskForm):
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
        ],
    )
    submit = SubmitField("Create")


## Edit Tag Form
class EditTagForm(FlaskForm):
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
        ],
    )
    submit = SubmitField("Save")


# Index Page
@app.route("/")
def index():
    """
    If the user is logged in, redirect to home page. If there is no logged
    in user, redirect to the sign-up page.
    """
    if current_user is None:
        return redirect("/signup")
    else:
        return redirect("/home")


## Sign Up Page
@app.route("/signup", methods=["GET", "POST"])
def signup():
    """
    Handles new user registration.
    Validates form, hashes password, saves user to database, logs them in.
    """

    form = SignUpForm()
    if form.validate_on_submit():
        if form.password.data == form.confirm_password.data:
            user = Users.query.filter_by(email=form.email.data).first()
            if user is None:
                # Hash the password
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


## Log In Page
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handles logging users in with flask_login.
    Validates form, verifies password, logs in user.
    If user does not exist them the function returns an error message.
    """

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


## Logout User
@app.route("/logout")
@login_required
def logout():
    """
    Logs out user, redirects to login page.
    """
    logout_user()
    flash("Successfully Logged Out.")
    return redirect("/login")


## Home Page
@app.route("/home")
@login_required
def home():
    return render_template("home.html", username=current_user.username)


## Gallery Page
@app.route("/gallery", methods=["GET", "POST"])
@login_required
def gallery():
    """
    Handles the photo gallery page.
    Checks if user has photos, passes them to the page, runs checks to create
    new tags if it doesn't already exist.

    Includes sorting features for the photo query if the user selects an option.
    """

    if Photos.query.filter_by(user=current_user.id).count() > 0:
        has_photos = True
    else:
        has_photos = False

    photos = []

    form = CreateTagForm()

    img_filter = None
    sort_by = "Newest"

    if request.method == "POST":
        filter_button = request.form.get("filter_button")
        sort_button = request.form.get("sort_button")

        if form.tag_name.data is not None:
            tag = [form.tag_name.data, form.tag_colour.data]
        else:
            tag = None
        user_tags = current_user.tags

        # Filter photo query
        if filter_button == "None":
            session["filter_button"] = None
        elif filter_button:
            session["filter_button"] = filter_button
        else:
            filter_button = session.get("filter_button")

        if sort_button:
            session["sort_button"] = sort_button
        else:
            sort_button = session.get("sort_button")

        if session.get("filter_button"):
            img_filter = json.loads(session["filter_button"].replace("'", '"'))

        sort_by = session.get("sort_button", "Newest")

        if tag is not None:
            if user_tags and tag in user_tags:
                flash("Tag name/colour already exists. Please try again.")
            else:
                selected_photo = request.form.get("selected_photo")
                user_tags.append(tag)
                current_user.tags = user_tags
                flag_modified(current_user, "tags")

                photo = Photos.query.filter_by(id=selected_photo).first()
                photo_tags = [tag]

                for photo_tag in photo.tags:
                    photo_tags.append(photo_tag)

                photo.tags = photo_tags
                flag_modified(photo, "tags")

                db.session.commit()
                flash("Tag created.")
    else:
        if session.get("filter_button"):
            img_filter = json.loads(session["filter_button"].replace("'", '"'))
        sort_by = session.get("sort_button", "Newest")

    # Sort photo query
    if sort_by == "Newest":
        for photo in Photos.query.filter_by(user=current_user.id).order_by(
            Photos.date_added.desc()
        ):
            if img_filter:
                if img_filter in photo.tags:
                    photos.append(photo)
            else:
                photos.append(photo)
    elif sort_by == "Oldest":
        for photo in Photos.query.filter_by(user=current_user.id).order_by(
            Photos.date_added.asc()
        ):
            if img_filter:
                if img_filter in photo.tags:
                    photos.append(photo)
            else:
                photos.append(photo)

    return render_template(
        "gallery.html",
        photos=photos,
        tags=current_user.tags,
        form=form,
        img_filter=img_filter,
        sort_by=sort_by,
        has_photos=has_photos,
    )


## Update User
@app.route("/update-user", methods=["GET", "POST"])
@login_required
def update_user():
    """
    Handles updating user information.
    Validates form, checks if information is already in use, updates database
    from ID of the logged in user.
    """
    form = UpdateAccountForm()

    if form.validate_on_submit():
        if form.username.data != current_user.username:
            if Users.query.filter_by(username=form.username.data).first():
                flash("Username already exists.")
                return render_template("update_user.html", form=form)
            else:
                current_user.username = form.username.data

        if form.email.data != current_user.email:
            if Users.query.filter_by(email=form.email.data).first():
                flash("Email already exists.")
                return render_template("update_user.html", form=form)
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
                return render_template("update_user.html", form=form)

        try:
            db.session.commit()
            flash("Account info updated.")
            return render_template("update_user.html", form=form)
        except:
            flash("An error has occured. Please try again.")
            return render_template("update_user.html", form=form)

    return render_template("update_user.html", form=form)


## Delete User
@app.route("/delete-user")
@login_required
def delete_user():
    """
    Handles deleting logged in user.
    Gets current user, logs them out, deletes database record, returns to main
    index.
    """
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


## Upload Photo
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """
    Handles uploading photos.
    Validates form, checks if the photo is valid, creates the image file in
    uploads folder, adds photo information to the database.
    """
    form = PhotoForm()

    if form.validate_on_submit():
        photo = form.photo.data

        try:
            Image.open(photo).verify()
            photo.seek(0)
        except:
            flash(
                """The uploaded image is either invalid or contains corrupted
                data. Please try again with a different file."""
            )

            return redirect("/upload")

        if photo:
            folder_path = os.path.join(
                app.config["UPLOADED_PHOTOS_DEST"],
                str(current_user.id),
            )
            os.makedirs(folder_path, exist_ok=True)

            file_name = secure_filename(
                f"{ datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                }_{photo.filename}"
            )
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


## Add tag to specified photo
@app.route("/add_tag/<photo_id>")
@login_required
def add_tag(photo_id):
    """
    Handles adding tags to a photo.
    Receives tag information, gets photo from database, adds tag to the photo in
    the database, redirects to gallery.
    """
    tag_name = request.args.get("tag_name")
    tag_colour = request.args.get("tag_colour")

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

    return redirect("/gallery")


## Remove tag from specific photo
@app.route("/remove_tag/<photo_id>")
@login_required
def remove_tag(photo_id):
    """
    Handles removing tags from a photo.
    Receives tag information, gets photo from database, searches photo for the
    tag, removes the tag, redirects to gallery.
    """
    tag_name = request.args.get("tag_name")
    tag_colour = request.args.get("tag_colour")

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

    return redirect("/gallery")


## Delete tag
@app.route("/delete_tag/<tag>")
@login_required
def delete_tag(tag):
    """
    Handles deleting tags from the user.
    Receives tag information, searches the user's tags, deletes the tag from
    list, updates the database.
    """
    tag = json.loads(tag.replace("'", '"'))

    user_tags = current_user.tags

    if tag in user_tags:
        for photo in Photos.query.filter_by(user=current_user.id):
            photo_tags = []

            for existing_tag in photo.tags:
                photo_tags.append(existing_tag)

            if tag in photo_tags:
                photo_tags.pop(photo_tags.index(tag))
                photo.tags = photo_tags

                flag_modified(photo, "tags")

        user_tags.pop(user_tags.index(tag))
        current_user.tags = user_tags
        flag_modified(current_user, "tags")

        db.session.commit()
        flash("Tag successfully deleted.")
    else:
        flash("Tag not found. Please try again.")

    return redirect("/manage_tags")


## Delete Photo
@app.route("/delete_photo/<photo_id>")
@login_required
def delete_photo(photo_id):
    """
    Handles deleting photos.
    Receives photo from the database, removes the record, redirects to the
    gallery.
    """
    photo = Photos.query.get_or_404(photo_id)

    try:
        db.session.delete(photo)
        db.session.commit()
        flash("Successfully deleted photo.")
    except:
        flash("An error has occurred, please try again.")

    return redirect("/gallery")


## Manage tags Page
@app.route("/manage_tags", methods=["GET", "POST"])
@login_required
def manage_tags():
    """
    Validates form, edits tag information, updates database.
    """
    form = EditTagForm()

    if form.validate_on_submit():
        tag = [form.tag_name.data, form.tag_colour.data]
        original_tag = json.loads(request.form.get("original_tag").replace("'", '"'))

        try:
            tag_index = current_user.tags.index(original_tag)
        except:
            tag_index = None

        if tag_index is not None:
            if tag in current_user.tags:
                flash("Tag name/colour already exists. Please try again.")
            else:
                current_user.tags[tag_index] = tag
                flag_modified(current_user, "tags")
                flash("Successfully updated tag.")

                for photo in Photos.query.filter_by(user=current_user.id):
                    photo_tags = []

                    for existing_tag in photo.tags:
                        photo_tags.append(existing_tag)

                    if original_tag in photo_tags:
                        photo_tags[photo_tags.index(original_tag)] = tag
                        photo.tags = photo_tags

                        flag_modified(photo, "tags")

                db.session.commit()

    return render_template(
        "manage_tags.html",
        tags=current_user.tags,
        form=form,
    )


## Run Flask / Setup database
if __name__ == "__main__":
    db_init(app)
    app.run()
