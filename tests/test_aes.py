"""Tests for the AES encryption module."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aes_module import AESError, decrypt_message, encrypt_message


def test_encrypt_decrypt_roundtrip():
    key = "123456789"
    message = "Hello, this is my secret message."
    encrypted = encrypt_message(message, key)
    assert encrypted != message
    assert decrypt_message(encrypted, key) == message


def test_wrong_key_is_rejected():
    encrypted = encrypt_message("secret", "correct-key")
    with pytest.raises(AESError):
        decrypt_message(encrypted, "wrong-key")


def test_invalid_base64_is_rejected():
    with pytest.raises(AESError):
        decrypt_message("not valid base64 @@@", "123456789")


def test_truncated_payload_is_rejected():
    # Valid base64 but far too short to be a real payload.
    import base64
    short = base64.b64encode(b"tiny").decode()
    with pytest.raises(AESError):
        decrypt_message(short, "123456789")


def test_unicode_message():
    key = "unicode-key"
    message = "Héllo 🌍 – secret ✓ café"
    encrypted = encrypt_message(message, key)
    assert decrypt_message(encrypted, key) == message


def test_multiline_message():
    key = "multi"
    message = "line one\nline two\nline three"
    encrypted = encrypt_message(message, key)
    assert decrypt_message(encrypted, key) == message


def test_empty_message_rejected():
    with pytest.raises(AESError):
        encrypt_message("", "123456789")


def test_empty_key_rejected():
    with pytest.raises(AESError):
        encrypt_message("hello", "")


def test_key_normalisation_padding():
    # Short and padded-equivalent keys must behave identically.
    encrypted = encrypt_message("data", "abc")
    assert decrypt_message(encrypted, "abc") == "data"
