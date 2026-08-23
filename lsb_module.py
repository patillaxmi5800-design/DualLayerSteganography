"""LSB steganography module for StegoSecure."""

from __future__ import annotations

from pathlib import Path
from PIL import Image, UnidentifiedImageError


class LSBError(Exception):
    """Application-level error raised for any LSB failure."""


HEADER_BITS = 32


def _message_to_bits(message: str) -> str:
    """Convert UTF-8 text to binary."""
    data = message.encode("utf-8")
    return "".join(format(byte, "08b") for byte in data)


def _bits_to_message(bits: str) -> str:
    """Convert binary data back to UTF-8 text."""
    if len(bits) % 8 != 0:
        raise LSBError("Invalid hidden message data.")

    data = bytearray()

    for i in range(0, len(bits), 8):
        data.append(int(bits[i:i + 8], 2))

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LSBError("Invalid hidden message data.") from exc


def _get_pixels(image: Image.Image) -> list:
    """Return image pixels."""
    getter = getattr(image, "get_flattened_data", None)

    if getter is not None:
        return list(getter())

    return list(image.getdata())


def hide_message(image_path: str, message: str, output_path: str) -> str:
    """Hide an encrypted Base64 message inside an image."""

    try:
        image = Image.open(image_path)
        image.load()
    except (FileNotFoundError, UnidentifiedImageError, OSError) as exc:
        raise LSBError("Corrupted or invalid image.") from exc

    # Always use RGB.
    image = image.convert("RGB")

    width, height = image.size
    capacity = width * height * 3

    # Convert message to bytes/bits.
    message_bits = _message_to_bits(message)

    # Store message length in bits using 32 bits.
    message_length = len(message_bits)

    if message_length >= 2**32:
        raise LSBError("Message is too large.")

    length_bits = format(message_length, "032b")

    # Header + encrypted payload.
    bits = length_bits + message_bits

    if len(bits) > capacity:
        raise LSBError("Message is too large for this image.")

    pixels = _get_pixels(image)

    new_pixels = []
    bit_index = 0
    total_bits = len(bits)

    for pixel in pixels:

        channels = list(pixel)

        for channel in range(3):

            if bit_index < total_bits:

                bit = bits[bit_index]

                channels[channel] = (
                    channels[channel] & ~1
                ) | int(bit)

                bit_index += 1

        new_pixels.append(tuple(channels))

    image.putdata(new_pixels)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    try:
        image.save(output, format="PNG")
    except OSError as exc:
        raise LSBError("Could not save the stego image.") from exc

    return str(output)


def extract_message(image_path: str) -> str:
    """Extract the hidden encrypted message from a stego image."""

    try:
        image = Image.open(image_path)
        image.load()
    except (FileNotFoundError, UnidentifiedImageError, OSError) as exc:
        raise LSBError("Corrupted or invalid image.") from exc

    image = image.convert("RGB")

    width, height = image.size
    capacity = width * height * 3

    pixels = _get_pixels(image)

    # Extract the first 32 bits (message length).
    header_bits = []

    for pixel in pixels:

        for channel in range(3):

            header_bits.append(str(pixel[channel] & 1))

            if len(header_bits) == HEADER_BITS:
                break

        if len(header_bits) == HEADER_BITS:
            break

    if len(header_bits) < HEADER_BITS:
        raise LSBError("Invalid hidden message data.")

    message_length = int("".join(header_bits), 2)

    # Validate length.
    if message_length <= 0:
        raise LSBError("No hidden message was found in this image.")

    if HEADER_BITS + message_length > capacity:
        raise LSBError("Invalid hidden message data.")

    # Extract exactly the number of bits stored in the header.
    payload_bits = []

    bit_position = 0

    for pixel in pixels:

        for channel in range(3):

            # Skip the first 32 header bits.
            if bit_position < HEADER_BITS:
                bit_position += 1
                continue

            if len(payload_bits) < message_length:

                payload_bits.append(str(pixel[channel] & 1))

            bit_position += 1

            if len(payload_bits) == message_length:
                break

        if len(payload_bits) == message_length:
            break

    if len(payload_bits) != message_length:
        raise LSBError("Invalid hidden message data.")

    return _bits_to_message("".join(payload_bits))
