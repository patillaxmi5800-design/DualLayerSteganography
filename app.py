"""StegoSecure - Dual Layer Steganography Using AES and LSB Algorithms.

A Flask web application that protects a secret message with two layers:

1. AES encryption (EAX mode) turns the message into an authenticated,
   Base64-encoded payload.
2. LSB steganography hides that payload inside the pixels of a cover image.

Includes user authentication (Flask-Login + Flask-SQLAlchemy).

Run with:  python app.py
"""

from __future__ import annotations

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

from aes_module import AESError, decrypt_message, encrypt_message
from config import (
    ALLOWED_EXTENSIONS,
    Config,
    DEMO_EMAIL,
    DEMO_FULL_NAME,
    DEMO_PASSWORD,
    DEMO_USERNAME,
    OUTPUT_DIR,
    OUTPUT_IMAGE_NAME,
    UPLOAD_DIR,
    resource_path,
)
from lsb_module import LSBError, extract_message, hide_message
from models import User, db

app = Flask(
    __name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static"),
)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this feature."
login_manager.login_message_category = "error"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


# --------------------------------------------------------------------------- #
# Startup: directories, database, demo account
# --------------------------------------------------------------------------- #

def _ensure_directories() -> None:
    """Create the uploads/ and output/ folders on startup if missing."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def _seed_demo_user() -> None:
    """Create the built-in demo account if it does not already exist."""
    if User.query.filter_by(username=DEMO_USERNAME).first() is None:
        user = User(
            full_name=DEMO_FULL_NAME, username=DEMO_USERNAME, email=DEMO_EMAIL
        )
        user.set_password(DEMO_PASSWORD)
        db.session.add(user)
        db.session.commit()


def init_app_state() -> None:
    """Prepare directories and database. Safe to call more than once."""
    _ensure_directories()
    with app.app_context():
        db.create_all()
        _seed_demo_user()


init_app_state()


@app.context_processor
def inject_demo_credentials():
    """Expose demo credentials to templates (login/register hint boxes)."""
    return {"demo_username": DEMO_USERNAME, "demo_password": DEMO_PASSWORD}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _validate_and_save_upload(file_storage) -> Path:
    """Validate an uploaded image and save it under uploads/ with a safe name.

    Validates both the extension (allowlist) and the actual image content
    (Pillow ``verify``). Returns the saved path. Raises :class:`ValueError`
    with a friendly message on any problem.
    """
    if file_storage is None or file_storage.filename == "":
        raise ValueError("Please select an image.")

    original = secure_filename(file_storage.filename)
    suffix = Path(original).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported image type.")

    safe_name = f"{uuid.uuid4().hex}{suffix}"
    saved_path = UPLOAD_DIR / safe_name
    file_storage.save(saved_path)

    try:
        with Image.open(saved_path) as img:
            img.verify()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        saved_path.unlink(missing_ok=True)
        raise ValueError("Corrupted or invalid image.") from exc

    return saved_path


# --------------------------------------------------------------------------- #
# Authentication routes
# --------------------------------------------------------------------------- #

@app.route("/register", methods=["GET", "POST"])
def register():
    """Create a new user account."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("register.html")

    full_name = request.form.get("full_name", "").strip()
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    error = None
    if not full_name:
        error = "Please enter your full name."
    elif not username:
        error = "Please enter a username."
    elif len(username) < 3 or len(username) > 30:
        error = "Username must be between 3 and 30 characters."
    elif not all(c.isalnum() or c in "_-." for c in username):
        error = "Username may only contain letters, numbers, _-. characters."
    elif not email:
        error = "Please enter an email address."
    elif not _EMAIL_RE.match(email):
        error = "Please enter a valid email address."
    elif not password:
        error = "Please enter a password."
    elif len(password) < 6:
        error = "Password must be at least 6 characters long."
    elif password != confirm:
        error = "Passwords do not match."
    elif User.query.filter_by(username=username).first() is not None:
        error = "That username is already taken."
    elif User.query.filter_by(email=email).first() is not None:
        error = "That email is already registered."

    if error:
        flash(error, "error")
        return render_template(
            "register.html", full_name=full_name, username=username, email=email
        )

    user = User(full_name=full_name, username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    flash("Account created successfully. Please log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log an existing user in using their username or email."""
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("login.html")

    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")

    if not identifier or not password:
        flash("Please enter your username/email and password.", "error")
        return render_template("login.html", identifier=identifier)

    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    if user is None or not user.check_password(password):
        flash("Invalid username/email or password.", "error")
        return render_template("login.html", identifier=identifier)

    login_user(user)
    flash(f"Welcome back, {user.full_name}!", "success")

    next_page = request.args.get("next", "")
    if next_page.startswith("/") and not next_page.startswith("//"):
        return redirect(next_page)
    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    """Log the current user out."""
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------- #
# Main pages
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    """Home page (public; shows authenticated navigation when logged in)."""
    return render_template("index.html", active_page="home")


@app.route("/about")
def about():
    """About page."""
    return render_template("about.html", active_page="about")


@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt():
    """Encrypt a message and hide it inside an uploaded cover image."""
    if request.method == "GET":
        return render_template("encrypt.html", active_page="encrypt")

    message = request.form.get("message", "")
    key = request.form.get("key", "")
    image_file = request.files.get("image")

    if not message.strip():
        flash("Please enter a secret message.", "error")
        return render_template("encrypt.html", active_page="encrypt")
    if not key:
        flash("Please enter an AES key.", "error")
        return render_template("encrypt.html", active_page="encrypt")

    saved_path = None
    try:
        saved_path = _validate_and_save_upload(image_file)
        encrypted_payload = encrypt_message(message, key)
        output_path = OUTPUT_DIR / OUTPUT_IMAGE_NAME
        hide_message(str(saved_path), encrypted_payload, str(output_path))
    except (ValueError, AESError, LSBError) as exc:
        flash(f"{exc}", "error")
        return render_template("encrypt.html", active_page="encrypt")
    finally:
        if saved_path is not None:
            Path(saved_path).unlink(missing_ok=True)

    flash("Encryption completed successfully!", "success")
    return render_template(
        "encrypt.html", active_page="encrypt", download_ready=True
    )


@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt():
    """Extract and decrypt a hidden message from an uploaded stego image."""
    if request.method == "GET":
        return render_template("decrypt.html", active_page="decrypt")

    key = request.form.get("key", "")
    image_file = request.files.get("image")

    if not key:
        flash("Please enter an AES key.", "error")
        return render_template("decrypt.html", active_page="decrypt")

    saved_path = None
    try:
        saved_path = _validate_and_save_upload(image_file)
        encrypted_payload = extract_message(str(saved_path))
        plaintext = decrypt_message(encrypted_payload, key)
    except (ValueError, LSBError, AESError) as exc:
        flash(f"{exc}", "error")
        return render_template("decrypt.html", active_page="decrypt")
    finally:
        if saved_path is not None:
            Path(saved_path).unlink(missing_ok=True)

    flash("Message decrypted successfully!", "success")
    return render_template(
        "decrypt.html", active_page="decrypt", decrypted_message=plaintext
    )


@app.route("/download")
@login_required
def download():
    """Serve the generated stego image as a file download."""
    output_path = OUTPUT_DIR / OUTPUT_IMAGE_NAME
    if not output_path.exists():
        flash("No encrypted image is available to download.", "error")
        return redirect(url_for("encrypt"))
    return send_file(
        output_path,
        as_attachment=True,
        download_name="encrypted_image.png",
        mimetype="image/png",
    )


# --------------------------------------------------------------------------- #
# Error handlers (no tracebacks shown to users)
# --------------------------------------------------------------------------- #

@app.errorhandler(400)
def bad_request(_error):
    return render_template("error.html", code=400,
                           message="Bad request."), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404,
                           message="Page not found."), 404


@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413,
                           message="Image file is too large (max 20 MB)."), 413


@app.errorhandler(500)
def server_error(_error):
    return render_template("error.html", code=500,
                           message="An unexpected error occurred."), 500


if __name__ == "__main__":
    import os

    # Port is configurable via STEGOSECURE_PORT (default 5000) so the app can
    # avoid a clash if another process already holds the default port.
    port = int(os.environ.get("STEGOSECURE_PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
