"""Tests for the LSB steganography module."""

import os
import sys

import pytest
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from lsb_module import LSBError, extract_message, hide_message


def _make_image(path, size=(200, 200), color=(120, 90, 200), mode="RGB"):
    Image.new(mode, size, color).save(path)
    return path


def test_hide_and_extract(tmp_path):
    cover = _make_image(tmp_path / "cover.png")
    out = tmp_path / "stego.png"
    payload = "SGVsbG8gd29ybGQ="  # sample base64-like text
    hide_message(str(cover), payload, str(out))
    assert out.exists()
    assert extract_message(str(out)) == payload


def test_output_is_png(tmp_path):
    cover = _make_image(tmp_path / "cover.png")
    out = tmp_path / "stego.png"
    hide_message(str(cover), "abc123", str(out))
    with Image.open(out) as img:
        assert img.format == "PNG"


def test_capacity_validation(tmp_path):
    # Tiny image cannot hold a large payload.
    cover = _make_image(tmp_path / "tiny.png", size=(4, 4))
    out = tmp_path / "stego.png"
    big_message = "A" * 500
    with pytest.raises(LSBError) as exc:
        hide_message(str(cover), big_message, str(out))
    assert "too large" in str(exc.value).lower()


def test_missing_marker(tmp_path):
    # A plain image with no embedded message.
    plain = _make_image(tmp_path / "plain.png", size=(50, 50), color=(10, 20, 30))
    with pytest.raises(LSBError) as exc:
        extract_message(str(plain))
    assert "no hidden message" in str(exc.value).lower()


def test_rgb_conversion_from_grayscale(tmp_path):
    # A grayscale (L mode) cover image must still work.
    cover = _make_image(tmp_path / "gray.png", size=(100, 100), color=128, mode="L")
    out = tmp_path / "stego.png"
    hide_message(str(cover), "graytest", str(out))
    assert extract_message(str(out)) == "graytest"


def test_invalid_image(tmp_path):
    fake = tmp_path / "fake.png"
    fake.write_text("this is not an image")
    with pytest.raises(LSBError) as exc:
        extract_message(str(fake))
    assert "corrupted or invalid" in str(exc.value).lower()


def test_unicode_payload(tmp_path):
    cover = _make_image(tmp_path / "cover.png")
    out = tmp_path / "stego.png"
    payload = "café-señor-✓"
    hide_message(str(cover), payload, str(out))
    assert extract_message(str(out)) == payload
