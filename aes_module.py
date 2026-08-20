"""AES encryption module for StegoSecure.

Implements the academic dual-layer specification using AES in EAX mode,
which provides both confidentiality (encryption) and integrity/authenticity
(a verification tag). The user-supplied key is normalised to 16 bytes as
required by the project specification.

NOTE (security): This module deliberately follows the required academic
algorithm which pads/truncates the user key to 16 bytes. A real production
system should derive the key from the password using a KDF such as PBKDF2 or
scrypt with a random salt. See README.md for details.
"""

from __future__ import annotations

import base64

from Crypto.Cipher import AES


class AESError(Exception):
    """Application-level error raised for any AES failure.

    Using a dedicated exception lets the web layer show a clean, friendly
    message instead of leaking a Python traceback to the user.
    """


# The EAX nonce and authentication tag are both 16 bytes long. Anything
# shorter than the two combined cannot possibly be a valid payload.
_NONCE_SIZE = 16
_TAG_SIZE = 16
_MIN_PAYLOAD = _NONCE_SIZE + _TAG_SIZE

_WRONG_KEY_MESSAGE = "Wrong AES key or invalid encrypted image."


def _normalise_key(key: str) -> bytes:
    """Normalise a user key to exactly 16 bytes.

    Follows the required academic specification: ``key.ljust(16)[:16]``.
    """
    if key is None:
        raise AESError("Please enter an AES key.")
    if not isinstance(key, str):
        raise AESError("Please enter an AES key.")
    if key == "":
        raise AESError("Please enter an AES key.")
    return key.ljust(16)[:16].encode("utf-8")


def encrypt_message(message: str, key: str) -> str:
    """Encrypt ``message`` with ``key`` and return a Base64 string.

    The returned string encodes ``nonce + tag + ciphertext`` so that the
    matching :func:`decrypt_message` call can rebuild the cipher and verify
    the authentication tag.
    """
    if message is None or message == "":
        raise AESError("Please enter a secret message.")

    normalised = _normalise_key(key)

    try:
        cipher = AES.new(normalised, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
    except AESError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        raise AESError("Encryption failed. Please try again.") from exc

    payload = cipher.nonce + tag + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def decrypt_message(encrypted_message: str, key: str) -> str:
    """Decrypt a Base64 payload produced by :func:`encrypt_message`.

    Raises :class:`AESError` with a friendly message for any failure mode:
    invalid Base64, a truncated payload, a wrong key (tag mismatch) or
    non-UTF-8 output.
    """
    if encrypted_message is None or encrypted_message == "":
        raise AESError(_WRONG_KEY_MESSAGE)

    normalised = _normalise_key(key)

    # Step 1: Base64 decode.
    try:
        payload = base64.b64decode(encrypted_message, validate=True)
    except Exception as exc:
        raise AESError(_WRONG_KEY_MESSAGE) from exc

    # Step 2: validate payload length.
    if len(payload) < _MIN_PAYLOAD:
        raise AESError(_WRONG_KEY_MESSAGE)

    # Steps 3-5: split the payload into its parts.
    nonce = payload[:_NONCE_SIZE]
    tag = payload[_NONCE_SIZE:_MIN_PAYLOAD]
    ciphertext = payload[_MIN_PAYLOAD:]

    # Steps 6-8: rebuild the cipher, decrypt and verify the tag.
    try:
        cipher = AES.new(normalised, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as exc:
        # A ValueError here means the tag did not verify, i.e. wrong key
        # or a tampered/invalid image.
        raise AESError(_WRONG_KEY_MESSAGE) from exc

    # Step 9: decode UTF-8.
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AESError(_WRONG_KEY_MESSAGE) from exc
