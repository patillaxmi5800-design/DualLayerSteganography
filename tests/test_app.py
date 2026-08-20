"""Tests for the Flask application routes (authenticated pages)."""

import io
import os
import sys

import pytest
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as app_module
from models import User, db


def _ensure_test_user() -> int:
    """Make sure a known test user exists; return its id."""
    with app_module.app.app_context():
        user = User.query.filter_by(username="tester").first()
        if user is None:
            user = User(
                full_name="Test User",
                username="tester",
                email="tester@example.com",
            )
            user.set_password("secret123")
            db.session.add(user)
            db.session.commit()
        return user.id


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    uid = _ensure_test_user()
    with app_module.app.test_client() as client:
        # Log the client in via Flask-Login's session key.
        with client.session_transaction() as sess:
            sess["_user_id"] = str(uid)
            sess["_fresh"] = True
        yield client


def _image_bytes(size=(200, 200), color=(120, 90, 200), fmt="PNG"):
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format=fmt)
    buf.seek(0)
    return buf


def test_home_route(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Welcome to StegoSecure" in resp.data


def test_about_page(client):
    resp = client.get("/about")
    assert resp.status_code == 200
    assert b"About StegoSecure" in resp.data


def test_encrypt_page(client):
    resp = client.get("/encrypt")
    assert resp.status_code == 200
    assert b"Encrypt Secret Message" in resp.data


def test_decrypt_page(client):
    resp = client.get("/decrypt")
    assert resp.status_code == 200
    assert b"Decrypt Secret Message" in resp.data


def test_missing_message(client):
    data = {
        "message": "",
        "key": "123456789",
        "image": (_image_bytes(), "cover.png"),
    }
    resp = client.post("/encrypt", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Please enter a secret message" in resp.data


def test_missing_key(client):
    data = {
        "message": "hello",
        "key": "",
        "image": (_image_bytes(), "cover.png"),
    }
    resp = client.post("/encrypt", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Please enter an AES key" in resp.data


def test_invalid_upload(client):
    fake = io.BytesIO(b"this is not an image")
    data = {
        "message": "hello",
        "key": "123456789",
        "image": (fake, "fake.png"),
    }
    resp = client.post("/encrypt", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Corrupted or invalid image" in resp.data


def test_unsupported_extension(client):
    data = {
        "message": "hello",
        "key": "123456789",
        "image": (io.BytesIO(b"data"), "note.txt"),
    }
    resp = client.post("/encrypt", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Unsupported image type" in resp.data


def test_full_encrypt_then_download(client):
    data = {
        "message": "Hello, this is my secret message.",
        "key": "123456789",
        "image": (_image_bytes(), "cover.png"),
    }
    resp = client.post("/encrypt", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Encryption completed successfully" in resp.data

    dl = client.get("/download")
    assert dl.status_code == 200
    assert dl.headers["Content-Type"] == "image/png"


def test_404_error_page(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
    assert b"404" in resp.data
