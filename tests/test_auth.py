"""Tests for registration, login, logout and route protection."""

import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as app_module
from config import DEMO_PASSWORD, DEMO_USERNAME
from models import User


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client


def _suffix():
    return uuid.uuid4().hex[:8]


def _register(client, full_name, username, email, password, confirm=None):
    return client.post(
        "/register",
        data={
            "full_name": full_name,
            "username": username,
            "email": email,
            "password": password,
            "confirm": confirm if confirm is not None else password,
        },
    )


# ---------- registration ----------

def test_register_page_loads(client):
    resp = client.get("/register")
    assert resp.status_code == 200
    assert b"Create Your StegoSecure Account" in resp.data


def test_successful_registration(client):
    s = _suffix()
    resp = _register(client, "Alice Test", f"alice{s}", f"alice{s}@ex.com", "secret123")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]

    with app_module.app.app_context():
        user = User.query.filter_by(username=f"alice{s}").first()
        assert user is not None
        assert user.full_name == "Alice Test"
        # Password must be hashed, not stored in plain text.
        assert user.password_hash != "secret123"
        assert user.check_password("secret123")


def test_duplicate_username_rejected(client):
    s = _suffix()
    _register(client, "First", f"dup{s}", f"first{s}@ex.com", "secret123")
    resp = _register(client, "Second", f"dup{s}", f"second{s}@ex.com", "secret123")
    assert b"already taken" in resp.data


def test_duplicate_email_rejected(client):
    s = _suffix()
    _register(client, "First", f"userA{s}", f"same{s}@ex.com", "secret123")
    resp = _register(client, "Second", f"userB{s}", f"same{s}@ex.com", "secret123")
    assert b"already registered" in resp.data


def test_password_mismatch_rejected(client):
    s = _suffix()
    resp = _register(client, "Bob", f"bob{s}", f"bob{s}@ex.com", "secret123", "different")
    assert b"Passwords do not match" in resp.data


def test_invalid_email_rejected(client):
    s = _suffix()
    resp = _register(client, "Bad Email", f"bad{s}", "not-an-email", "secret123")
    assert b"valid email" in resp.data


def test_short_password_rejected(client):
    s = _suffix()
    resp = _register(client, "Shorty", f"short{s}", f"short{s}@ex.com", "123")
    assert b"at least 6 characters" in resp.data


# ---------- login / logout ----------

def test_login_page_loads(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Welcome Back" in resp.data


def test_login_with_username(client):
    s = _suffix()
    _register(client, "Carol", f"carol{s}", f"carol{s}@ex.com", "secret123")
    resp = client.post("/login", data={"identifier": f"carol{s}", "password": "secret123"})
    assert resp.status_code == 302
    assert "/login" not in resp.headers["Location"]  # redirected to home


def test_login_with_email(client):
    s = _suffix()
    _register(client, "Dave", f"dave{s}", f"dave{s}@ex.com", "secret123")
    resp = client.post("/login", data={"identifier": f"dave{s}@ex.com", "password": "secret123"})
    assert resp.status_code == 302
    assert "/login" not in resp.headers["Location"]


def test_login_wrong_password(client):
    s = _suffix()
    _register(client, "Eve", f"eve{s}", f"eve{s}@ex.com", "secret123")
    resp = client.post("/login", data={"identifier": f"eve{s}", "password": "wrongpass"})
    assert b"Invalid username/email or password" in resp.data


def test_login_unknown_user(client):
    resp = client.post("/login", data={"identifier": "nobody_here", "password": "whatever"})
    assert b"Invalid username/email or password" in resp.data


def test_logout_flow(client):
    s = _suffix()
    _register(client, "Frank", f"frank{s}", f"frank{s}@ex.com", "secret123")
    client.post("/login", data={"identifier": f"frank{s}", "password": "secret123"})
    resp = client.get("/logout", follow_redirects=True)
    assert b"Logged out successfully" in resp.data
    # Protected route now redirects to login.
    resp = client.get("/encrypt")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# ---------- protected routes ----------

def test_encrypt_requires_login(client):
    resp = client.get("/encrypt")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_decrypt_requires_login(client):
    resp = client.get("/decrypt")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


# ---------- demo account ----------

def test_demo_account_can_login(client):
    resp = client.post(
        "/login", data={"identifier": DEMO_USERNAME, "password": DEMO_PASSWORD}
    )
    assert resp.status_code == 302
    assert "/login" not in resp.headers["Location"]


def test_login_page_shows_demo_credentials(client):
    resp = client.get("/login")
    assert DEMO_USERNAME.encode() in resp.data
    assert DEMO_PASSWORD.encode() in resp.data
    assert b"Demo Account" in resp.data
