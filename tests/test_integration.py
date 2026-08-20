"""End-to-end integration test of the full dual-layer workflow.

Runs the exact required scenario:
    message = "Hello, this is my secret message."
    key     = "123456789"
and verifies the recovered plaintext matches exactly.
"""

import os
import sys

import pytest
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aes_module import AESError, decrypt_message, encrypt_message
from lsb_module import LSBError, extract_message, hide_message

MESSAGE = "Hello, this is my secret message."
KEY = "123456789"


def _make_test_image(path, size=(800, 600)):
    """Generate a sufficiently large PNG test image automatically."""
    img = Image.new("RGB", size, (200, 190, 255))
    img.save(path)
    return path


def test_full_dual_layer_roundtrip(tmp_path):
    cover = _make_test_image(tmp_path / "test.png")
    stego = tmp_path / "encrypted_image.png"

    # Encrypt -> embed.
    payload = encrypt_message(MESSAGE, KEY)
    hide_message(str(cover), payload, str(stego))
    assert stego.exists()

    # Extract -> decrypt.
    extracted = extract_message(str(stego))
    recovered = decrypt_message(extracted, KEY)
    assert recovered == MESSAGE


def test_wrong_key_fails_after_embedding(tmp_path):
    cover = _make_test_image(tmp_path / "test.png")
    stego = tmp_path / "encrypted_image.png"

    payload = encrypt_message(MESSAGE, KEY)
    hide_message(str(cover), payload, str(stego))

    extracted = extract_message(str(stego))
    with pytest.raises(AESError) as exc:
        decrypt_message(extracted, "wrong-key")
    assert "wrong aes key" in str(exc.value).lower()


def test_oversized_message_rejected(tmp_path):
    tiny = _make_test_image(tmp_path / "tiny.png", size=(8, 8))
    stego = tmp_path / "stego.png"
    payload = encrypt_message("X" * 300, KEY)
    with pytest.raises(LSBError) as exc:
        hide_message(str(tiny), payload, str(stego))
    assert "too large" in str(exc.value).lower()


def test_invalid_image_rejected(tmp_path):
    fake = tmp_path / "fake.png"
    fake.write_bytes(b"definitely not a real image file")
    with pytest.raises(LSBError):
        extract_message(str(fake))
