"""LSB steganography module for StegoSecure.

Hides an (already AES-encrypted) Base64 string inside the least significant
bits of an image's RGB channels, and extracts it back out again. Uses exactly
3 bits per pixel because each RGB pixel has three colour channels.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, UnidentifiedImageError


class LSBError(Exception):
    """Application-level error raised for any LSB failure."""


# A 16-bit marker that signals the end of the hidden payload. It is extremely
# unlikely to appear by chance in the leading bits of an unrelated image.
END_MARKER = "1111111111111110"


def _message_to_bits(message: str) -> str:
    """Convert a UTF-8 string into a string of '0'/'1' bits (8 bits/byte)."""
    data = message.encode("utf-8")
    return "".join(format(byte, "08b") for byte in data)


def _get_pixels(image: "Image.Image") -> list:
    """Return a flat list of pixel tuples, compatible across Pillow versions."""
    # Pillow 14 renames getdata() -> get_flattened_data(); support both.
    getter = getattr(image, "get_flattened_data", None)
    if getter is not None:
        return list(getter())
    return list(image.getdata())


def hide_message(image_path: str, message: str, output_path: str) -> str:
    """Hide ``message`` inside the image at ``image_path``.

    The result is always written as a PNG (a lossless format) so the embedded
    bits survive. Returns the output path on success.
    """
    try:
        image = Image.open(image_path)
        image.load()
    except (FileNotFoundError, UnidentifiedImageError, OSError) as exc:
        raise LSBError("Corrupted or invalid image.") from exc

    # Always work in RGB so we have exactly three channels per pixel.
    image = image.convert("RGB")
    width, height = image.size
    capacity = width * height * 3

    bits = _message_to_bits(message) + END_MARKER
    if len(bits) > capacity:
        raise LSBError("Message is too large for this image.")

    pixels = _get_pixels(image)
    new_pixels = []
    bit_index = 0
    total_bits = len(bits)

    for pixel in pixels:
        if bit_index >= total_bits:
            new_pixels.append(pixel)
            continue
        channels = list(pixel)
        for channel in range(3):
            if bit_index < total_bits:
                bit = bits[bit_index]
                channels[channel] = (channels[channel] & ~1) | int(bit)
                bit_index += 1
        new_pixels.append(tuple(channels))

    image.putdata(new_pixels)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        image.save(output, format="PNG")
    except OSError as exc:  # pragma: no cover - defensive
        raise LSBError("Could not save the stego image.") from exc

    return str(output)


def extract_message(image_path: str) -> str:
    """Extract a hidden message previously embedded with :func:`hide_message`.

    Raises :class:`LSBError` if the image is invalid or contains no marker.
    """
    try:
        image = Image.open(image_path)
        image.load()
    except (FileNotFoundError, UnidentifiedImageError, OSError) as exc:
        raise LSBError("Corrupted or invalid image.") from exc

    image = image.convert("RGB")
    pixels = _get_pixels(image)

    bits = []
    marker_len = len(END_MARKER)
    found = False

    for pixel in pixels:
        for channel in range(3):
            bits.append(str(pixel[channel] & 1))
            # Check the tail for the end marker as we go so we can stop early.
            if len(bits) >= marker_len and "".join(bits[-marker_len:]) == END_MARKER:
                found = True
                break
        if found:
            break

    if not found:
        raise LSBError("No hidden message was found in this image.")

    # Drop the marker, leaving only the payload bits.
    payload_bits = bits[:-marker_len]

    # The payload must be a whole number of bytes.
    if len(payload_bits) % 8 != 0:
        raise LSBError("Invalid hidden message data.")

    byte_values = bytearray()
    for i in range(0, len(payload_bits), 8):
        byte_bits = "".join(payload_bits[i:i + 8])
        byte_values.append(int(byte_bits, 2))

    try:
        return byte_values.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LSBError("Invalid hidden message data.") from exc
