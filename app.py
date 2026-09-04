"""
StegoSecure - Dual Layer Steganography Using AES and LSB Algorithms.

A Flask web application that protects a secret message with two layers:

1. AES encryption using EAX mode.
2. LSB steganography to hide the encrypted message inside an image.

Includes user authentication using Flask-Login and Flask-SQLAlchemy.
"""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

from aes_module import (
    AESError,
    decrypt_message,
    encrypt_message,
)

from config import (
    ALLOWED_EXTENSIONS,
    Config,
    OUTPUT_DIR,
    OUTPUT_IMAGE_NAME,
    UPLOAD_DIR,
    resource_path,
)

from lsb_module import (
    LSBError,
    extract_message,
    hide_message,
)

from models import User, db


# ===========================================================================
# FLASK APPLICATION
# ===========================================================================

app = Flask(
    __name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static"),
)

app.config.from_object(Config)

db.init_app(app)


# ===========================================================================
# FLASK-LOGIN CONFIGURATION
# ===========================================================================

login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

login_manager.login_message = (
    "Please log in to access this feature."
)

login_manager.login_message_category = "error"


# ===========================================================================
# EMAIL VALIDATION
# ===========================================================================

_EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)


# ===========================================================================
# USER LOADER
# ===========================================================================

@login_manager.user_loader
def load_user(user_id: str):
    """Load a user from the database."""

    try:
        return db.session.get(
            User,
            int(user_id)
        )

    except (TypeError, ValueError):
        return None


# ===========================================================================
# STARTUP
# ===========================================================================

def _ensure_directories() -> None:
    """Create upload and output directories."""

    UPLOAD_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


def _remove_demo_account() -> None:
    """
    Remove the old built-in demo account.

    This is useful because the demo account may already exist
    in the database from an earlier version of the application.
    """

    demo_user = User.query.filter(
        (User.username.ilike("demo"))
        |
        (User.email.ilike("demo@stegosecure.local"))
    ).first()

    if demo_user is not None:
        db.session.delete(demo_user)
        db.session.commit()


def init_app_state() -> None:
    """Prepare directories and database."""

    _ensure_directories()

    with app.app_context():

        # Create database tables if they do not exist.
        db.create_all()

        # Remove old demo account.
        _remove_demo_account()


init_app_state()


# ===========================================================================
# HELPER FUNCTIONS
# ===========================================================================

def _validate_and_save_upload(file_storage) -> Path:
    """Validate and save an uploaded image."""

    if (
        file_storage is None
        or file_storage.filename == ""
    ):
        raise ValueError(
            "Please select an image."
        )

    original = secure_filename(
        file_storage.filename
    )

    suffix = Path(original).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Unsupported image type."
        )

    safe_name = (
        f"{uuid.uuid4().hex}{suffix}"
    )

    saved_path = (
        UPLOAD_DIR / safe_name
    )

    file_storage.save(saved_path)

    try:

        with Image.open(saved_path) as img:
            img.verify()

    except (
        UnidentifiedImageError,
        OSError,
        ValueError,
    ) as exc:

        saved_path.unlink(
            missing_ok=True
        )

        raise ValueError(
            "Corrupted or invalid image."
        ) from exc

    return saved_path


# ===========================================================================
# REGISTER
# ===========================================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():
    """Create a new user account."""

    if current_user.is_authenticated:
        return redirect(
            url_for("index")
        )

    if request.method == "GET":
        return render_template(
            "register.html"
        )

    full_name = request.form.get(
        "full_name",
        ""
    ).strip()

    username = request.form.get(
        "username",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    password = request.form.get(
        "password",
        ""
    )

    confirm = request.form.get(
        "confirm",
        ""
    )

    error = None

    # -----------------------------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------------------------

    if not full_name:

        error = (
            "Please enter your full name."
        )

    elif not username:

        error = (
            "Please enter a username."
        )

    elif len(username) < 3 or len(username) > 30:

        error = (
            "Username must be between "
            "3 and 30 characters."
        )

    elif not all(
        c.isalnum() or c in "_-."
        for c in username
    ):

        error = (
            "Username may only contain "
            "letters, numbers, _ , - and . characters."
        )

    elif not email:

        error = (
            "Please enter an email address."
        )

    elif not _EMAIL_RE.match(email):

        error = (
            "Please enter a valid email address."
        )

    elif not password:

        error = (
            "Please enter a password."
        )

    elif len(password) < 6:

        error = (
            "Password must be at least "
            "6 characters long."
        )

    elif password != confirm:

        error = (
            "Passwords do not match."
        )

    elif User.query.filter_by(
        username=username
    ).first() is not None:

        error = (
            "That username is already taken."
        )

    elif User.query.filter_by(
        email=email
    ).first() is not None:

        error = (
            "That email is already registered."
        )

    # -----------------------------------------------------------------------
    # DISPLAY ERROR
    # -----------------------------------------------------------------------

    if error:

        flash(
            error,
            "error"
        )

        return render_template(
            "register.html",
            full_name=full_name,
            username=username,
            email=email,
        )

    # -----------------------------------------------------------------------
    # CREATE USER
    # -----------------------------------------------------------------------

    user = User(
        full_name=full_name,
        username=username,
        email=email,
    )

    user.set_password(password)

    db.session.add(user)

    db.session.commit()

    flash(
        "Account created successfully. Please log in.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ===========================================================================
# LOGIN
# ===========================================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():
    """Log an existing user in."""

    if current_user.is_authenticated:
        return redirect(
            url_for("index")
        )

    if request.method == "GET":

        return render_template(
            "login.html"
        )

    identifier = request.form.get(
        "identifier",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    if not identifier or not password:

        flash(
            "Please enter your username/email and password.",
            "error"
        )

        return render_template(
            "login.html",
            identifier=identifier,
        )

    user = User.query.filter(
        (User.username == identifier)
        |
        (User.email == identifier.lower())
    ).first()

    if (
        user is None
        or not user.check_password(password)
    ):

        flash(
            "Invalid username/email or password.",
            "error"
        )

        return render_template(
            "login.html",
            identifier=identifier,
        )

    login_user(user)

    flash(
        f"Welcome back, {user.full_name}!",
        "success"
    )

    next_page = request.args.get(
        "next",
        ""
    )

    if (
        next_page.startswith("/")
        and not next_page.startswith("//")
    ):

        return redirect(next_page)

    return redirect(
        url_for("index")
    )


# ===========================================================================
# FORGOT PASSWORD
# ===========================================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():
    """
    Reset password using username and registered email.
    """

    if current_user.is_authenticated:

        return redirect(
            url_for("index")
        )

    # -----------------------------------------------------------------------
    # SHOW FORGOT PASSWORD PAGE
    # -----------------------------------------------------------------------

    if request.method == "GET":

        return render_template(
            "forgot_password.html"
        )

    # -----------------------------------------------------------------------
    # GET FORM DATA
    # -----------------------------------------------------------------------

    username = request.form.get(
        "username",
        ""
    ).strip()

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    new_password = request.form.get(
        "new_password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    # -----------------------------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------------------------

    if not username or not email:

        flash(
            "Please enter your username and registered email.",
            "error"
        )

        return render_template(
            "forgot_password.html",
            username=username,
            email=email,
        )

    if not _EMAIL_RE.match(email):

        flash(
            "Please enter a valid email address.",
            "error"
        )

        return render_template(
            "forgot_password.html",
            username=username,
            email=email,
        )

    # -----------------------------------------------------------------------
    # FIND USER
    # -----------------------------------------------------------------------

    user = User.query.filter(
        (User.username == username)
        &
        (User.email == email)
    ).first()

    if user is None:

        flash(
            "Username and email do not match our records.",
            "error"
        )

        return render_template(
            "forgot_password.html",
            username=username,
            email=email,
        )

    # -----------------------------------------------------------------------
    # PASSWORD VALIDATION
    # -----------------------------------------------------------------------

    if not new_password:

        flash(
            "Please enter a new password.",
            "error"
        )

        return render_template(
            "forgot_password.html",
            username=username,
            email=email,
        )

    if len(new_password) < 6:

        flash(
            "New password must be at least 6 characters long.",
            "error"
        )

        return render_template(
            "forgot_password.html",
            username=username,
            email=email,
        )

    if new_password != confirm_password:

        flash(
            "Passwords do not match.",
            "error"
        )

        return render_template(
            "forgot_password.html",
            username=username,
            email=email,
        )

    # -----------------------------------------------------------------------
    # UPDATE PASSWORD
    # -----------------------------------------------------------------------

    user.set_password(
        new_password
    )

    db.session.commit()

    flash(
        "Password reset successfully. Please log in with your new password.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ===========================================================================
# LOGOUT
# ===========================================================================

@app.route("/logout")
@login_required
def logout():
    """Log the current user out."""

    logout_user()

    flash(
        "Logged out successfully.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ===========================================================================
# ADMIN DASHBOARD
# ===========================================================================

@app.route("/admin")
@login_required
def admin():
    """Admin dashboard for managing registered users."""

    if not current_user.is_admin:

        flash(
            "You are not authorized to access the admin dashboard.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    search = request.args.get(
        "search",
        ""
    ).strip()

    if search:

        users = User.query.filter(
            (User.username.ilike(
                f"%{search}%"
            ))
            |
            (User.full_name.ilike(
                f"%{search}%"
            ))
            |
            (User.email.ilike(
                f"%{search}%"
            ))
        ).order_by(
            User.created_at.desc()
        ).all()

    else:

        users = User.query.order_by(
            User.created_at.desc()
        ).all()

    total_users = User.query.count()

    return render_template(
        "admin.html",
        active_page="admin",
        users=users,
        total_users=total_users,
        search=search,
    )


# ===========================================================================
# DELETE USER
# ===========================================================================

@app.route(
    "/admin/delete/<int:user_id>",
    methods=["POST"]
)
@login_required
def delete_user(user_id):
    """Delete a registered user."""

    if not current_user.is_admin:

        flash(
            "You are not authorized to perform this action.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    user = db.session.get(
        User,
        user_id
    )

    if user is None:

        flash(
            "User not found.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    # Prevent deleting own account.
    if user.id == current_user.id:

        flash(
            "You cannot delete your own administrator account.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    # Prevent deleting another administrator.
    if user.is_admin:

        flash(
            "Administrator accounts cannot be deleted.",
            "error"
        )

        return redirect(
            url_for("admin")
        )

    username = user.username

    db.session.delete(user)

    db.session.commit()

    flash(
        f"User '{username}' deleted successfully.",
        "success"
    )

    return redirect(
        url_for("admin")
    )


# ===========================================================================
# HOME
# ===========================================================================

@app.route("/")
def index():
    """Home page."""

    return render_template(
        "index.html",
        active_page="home",
    )


# ===========================================================================
# ABOUT
# ===========================================================================

@app.route("/about")
def about():
    """About page."""

    return render_template(
        "about.html",
        active_page="about",
    )


# ===========================================================================
# ENCRYPT
# ===========================================================================

@app.route(
    "/encrypt",
    methods=["GET", "POST"]
)
@login_required
def encrypt():
    """Encrypt a message and hide it inside an uploaded image."""

    if request.method == "GET":

        return render_template(
            "encrypt.html",
            active_page="encrypt",
        )

    message = request.form.get(
        "message",
        ""
    )

    key = request.form.get(
        "key",
        ""
    )

    image_file = request.files.get(
        "image"
    )

    # -----------------------------------------------------------------------
    # MESSAGE VALIDATION
    # -----------------------------------------------------------------------

    if not message.strip():

        flash(
            "Please enter a secret message.",
            "error"
        )

        return render_template(
            "encrypt.html",
            active_page="encrypt",
        )

    # -----------------------------------------------------------------------
    # KEY VALIDATION
    # -----------------------------------------------------------------------

    if not key:

        flash(
            "Please enter an AES key.",
            "error"
        )

        return render_template(
            "encrypt.html",
            active_page="encrypt",
        )

    saved_path = None

    try:

        # Save uploaded image.
        saved_path = _validate_and_save_upload(
            image_file
        )

        # AES encryption.
        encrypted_payload = encrypt_message(
            message,
            key
        )

        # Output path.
        output_path = (
            OUTPUT_DIR
            /
            OUTPUT_IMAGE_NAME
        )

        # LSB steganography.
        hide_message(
            str(saved_path),
            encrypted_payload,
            str(output_path)
        )

    except (
        ValueError,
        AESError,
        LSBError,
    ) as exc:

        flash(
            str(exc),
            "error"
        )

        return render_template(
            "encrypt.html",
            active_page="encrypt",
        )

    finally:

        if saved_path is not None:

            Path(saved_path).unlink(
                missing_ok=True
            )

    flash(
        "Encryption completed successfully!",
        "success"
    )

    return render_template(
        "encrypt.html",
        active_page="encrypt",
        download_ready=True,
    )


# ===========================================================================
# DECRYPT
# ===========================================================================

@app.route(
    "/decrypt",
    methods=["GET", "POST"]
)
@login_required
def decrypt():
    """Extract and decrypt a hidden message."""

    if request.method == "GET":

        return render_template(
            "decrypt.html",
            active_page="decrypt",
        )

    key = request.form.get(
        "key",
        ""
    )

    image_file = request.files.get(
        "image"
    )

    # -----------------------------------------------------------------------
    # KEY VALIDATION
    # -----------------------------------------------------------------------

    if not key:

        flash(
            "Please enter an AES key.",
            "error"
        )

        return render_template(
            "decrypt.html",
            active_page="decrypt",
        )

    saved_path = None

    try:

        # Save uploaded encrypted image.
        saved_path = _validate_and_save_upload(
            image_file
        )

        # Extract encrypted message.
        encrypted_payload = extract_message(
            str(saved_path)
        )

        # AES decryption.
        plaintext = decrypt_message(
            encrypted_payload,
            key
        )

    except (
        ValueError,
        LSBError,
        AESError,
    ) as exc:

        flash(
            str(exc),
            "error"
        )

        return render_template(
            "decrypt.html",
            active_page="decrypt",
        )

    finally:

        if saved_path is not None:

            Path(saved_path).unlink(
                missing_ok=True
            )

    flash(
        "Message decrypted successfully!",
        "success"
    )

    return render_template(
        "decrypt.html",
        active_page="decrypt",
        decrypted_message=plaintext,
    )


# ===========================================================================
# DOWNLOAD
# ===========================================================================

@app.route("/download")
@login_required
def download():
    """Download the generated encrypted image."""

    output_path = (
        OUTPUT_DIR
        /
        OUTPUT_IMAGE_NAME
    )

    if not output_path.exists():

        flash(
            "No encrypted image is available to download.",
            "error"
        )

        return redirect(
            url_for("encrypt")
        )

    return send_file(
        output_path,
        as_attachment=True,
        download_name="encrypted_image.png",
        mimetype="image/png",
    )


# ===========================================================================
# ERROR HANDLERS
# ===========================================================================

@app.errorhandler(400)
def bad_request(error):

    return render_template(
        "error.html",
        code=400,
        message="Bad request.",
    ), 400


@app.errorhandler(404)
def not_found(error):

    return render_template(
        "error.html",
        code=404,
        message="Page not found.",
    ), 404


@app.errorhandler(413)
def too_large(error):

    return render_template(
        "error.html",
        code=413,
        message="Image file is too large (max 20 MB).",
    ), 413


@app.errorhandler(500)
def server_error(error):

    return render_template(
        "error.html",
        code=500,
        message="An unexpected error occurred.",
    ), 500


# ===========================================================================
# RUN APPLICATION
# ===========================================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "STEGOSECURE_PORT",
            "5000"
        )
    )

    app.run(
        host="127.0.0.1",
        port=port,
        debug=False,
    )