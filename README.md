# StegoSecure — Dual Layer Steganography Using AES and LSB Algorithms

StegoSecure is an MSc Computer Science final-year project. It protects a secret
message using **two independent security layers**, behind a full user
authentication system:

1. **AES Encryption** — the message is encrypted with AES (EAX mode), which also
   produces an authentication tag so tampering and wrong keys are detected.
2. **LSB Steganography** — the encrypted payload is hidden inside the least
   significant bits of a cover image's RGB pixels and saved as a PNG.

Only a logged-in user with the correct AES key can recover the original message.

---

## Objective

Demonstrate a practical, production-style implementation of dual-layer data
protection combining cryptography (AES) and information hiding (LSB
steganography), delivered as an authenticated Flask web application.

## Features

- **User authentication** — registration, login (by username *or* email),
  logout, using **Flask-Login** and **Werkzeug** password hashing
- **SQLite database** via **Flask-SQLAlchemy** (`data.db`, auto-created)
- Encrypt / Decrypt pages protected with `@login_required`
- Sidebar greets the signed-in user; premium centered login/register pages
- AES-EAX encryption with authentication (detects wrong keys / tampering)
- Real LSB steganography (3 bits per pixel across R, G, B channels)
- Drag-and-drop image upload with live preview; show/hide password & key toggles
- Download the generated stego image; full extract-and-decrypt workflow
- Friendly error handling with custom 400/404/413/500 pages — no tracebacks
- Responsive lavender/purple cybersecurity dashboard UI (Bootstrap 5 + custom CSS)
- Bootstrap and Poppins font are **vendored locally** — works fully offline
- Automated test suite (pytest)

## Technology Stack

| Layer      | Technology                                   |
|------------|----------------------------------------------|
| Backend    | Python 3.12+, Flask                          |
| Auth       | Flask-Login, Werkzeug password hashing       |
| Database   | SQLite via Flask-SQLAlchemy                  |
| Crypto     | PyCryptodome (AES-EAX)                        |
| Imaging    | Pillow (LSB embedding/extraction)            |
| Frontend   | HTML5, CSS3, JavaScript, Jinja2, Bootstrap 5 |
| Testing    | pytest                                       |

No Node.js, npm, React, Docker, cloud services, SMTP, OAuth, or Internet
connection are required.

## Architecture

```
Browser (HTML/CSS/JS + Bootstrap)
        |
   Flask routes (app.py)
   |    |         |
Flask-Login   aes_module   lsb_module
(auth)        (AES-EAX)    (Pillow LSB)
   |
models.py (SQLAlchemy User)  ->  data.db (SQLite)
```

### Authentication

- `User` model (`models.py`): `id, full_name, username, email, password_hash,
  created_at`. Username and email are unique.
- Passwords are hashed with `generate_password_hash` and checked with
  `check_password_hash` — plaintext passwords are never stored.
- Login accepts either the username or the email address.
- `/encrypt` and `/decrypt` require login; anonymous users are redirected to
  `/login`.

### AES Workflow

1. Normalise the user key to 16 bytes: `key.ljust(16)[:16].encode()`
2. Create an AES-EAX cipher, encrypt, and generate an authentication tag.
3. Store `nonce + tag + ciphertext`, then Base64-encode.

### LSB Workflow

1. Convert the cover image to RGB.
2. Convert the Base64 payload to bits and append the end marker
   `1111111111111110`.
3. Write one bit into the LSB of each R/G/B channel:
   `pixel[channel] = (pixel[channel] & ~1) | int(bit)`.
4. Save as PNG (lossless) so the bits survive.

### Encryption / Decryption Flow

```
Login -> Encrypt: Message -> AES-EAX -> Base64 -> LSB embed -> PNG -> Download
Login -> Decrypt: PNG -> LSB extract -> Base64 -> AES verify+decrypt -> Message
```

---

## Installation

> Prerequisite: Python 3.12+ on Windows 10/11.

The project ships with a `.venv` and installed dependencies. To recreate from
scratch:

```bash
cd DualLayerSteganography
python -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Running the Application

```bash
.venv\Scripts\python.exe app.py
```

or double-click **run.bat**, or run **run.ps1** in PowerShell. Then open:
<http://127.0.0.1:5000>

> If port 5000 is busy, choose another: `set STEGOSECURE_PORT=5001` (CMD) or
> `$env:STEGOSECURE_PORT=5001` (PowerShell), then run the app.

### Demo account

A demo account is seeded automatically (shown on the login page with a
one-click **Use demo** button):

- Username: `demo`
- Password: `demo1234`

## Testing

```bash
.venv\Scripts\python.exe -m pytest -q
```

## Project Structure

```
DualLayerSteganography/
├── app.py               # Flask app, routes, auth, error handlers
├── aes_module.py        # AES-EAX encryption/decryption
├── lsb_module.py        # LSB embed/extract
├── models.py            # SQLAlchemy User model + db
├── config.py            # Paths, limits, secret key, PyInstaller resource_path
├── data.db              # SQLite database (auto-created, gitignored)
├── requirements.txt
├── README.md
├── .gitignore
├── run.bat / run.ps1
├── tests/               # pytest suite (aes, lsb, auth, app, integration)
├── templates/           # Jinja2 templates (+ auth_base, error)
├── static/
│   ├── css/  (bootstrap.min.css [vendored], style.css)
│   ├── js/   (script.js)
│   ├── fonts/ (poppins-*.woff2 [vendored])
│   └── images/ (logo.png, security.png)
├── uploads/             # temporary uploads (auto-cleaned)
└── output/              # generated stego image
```

## Security Notes

- Uploads validated by extension allowlist **and** real image content (Pillow),
  saved under a generated collision-free filename; cover images deleted after use.
- Upload size capped at 20 MB (`MAX_CONTENT_LENGTH`); handled via a 413 page.
- Flask secret key configurable via `STEGOSECURE_SECRET_KEY`.
- Passwords hashed (never plaintext); AES keys and messages are never logged or
  placed in URLs; the encrypted AES payload is never displayed.
- Custom 400/404/413/500 handlers — raw tracebacks are never shown.

### Important cryptography note

The academic specification normalises the key with
`key.ljust(16)[:16].encode()`. This is intentional for the coursework. A **real
production system** should derive the key from the password using a Key
Derivation Function (e.g. PBKDF2 or scrypt) with a random salt, rather than
padding/truncating the password directly.

## Packaging with PyInstaller (optional)

The code is PyInstaller-friendly: writable data (`data.db`, `uploads/`,
`output/`) is stored next to the executable, while bundled read-only assets
(`templates/`, `static/`) are resolved via `config.resource_path` (which honours
`sys._MEIPASS`).

```bash
.venv\Scripts\python.exe -m pip install pyinstaller
.venv\Scripts\pyinstaller.exe --noconfirm --clean --onedir --name StegoSecure ^
  --add-data "templates;templates" ^
  --add-data "static;static" ^
  app.py
```

The built app appears under `dist\StegoSecure\`. Run `StegoSecure.exe`; the
database and folders are created alongside it on first launch.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python` not found | Install Python 3.12+ and ensure it is on PATH |
| Port 5000 in use | Set `STEGOSECURE_PORT` to another port |
| Wrong key error | The AES key must match the one used to encrypt |
| "Message too large" | Use a larger cover image |
| Forgot demo login | `demo` / `demo1234` (also shown on the login page) |

## Academic Demonstration / Viva

1. Start the app (`run.bat`) and open <http://127.0.0.1:5000>.
2. **Register** an account (or click **Use demo** on the login page:
   `demo` / `demo1234`), then **Login**. Your name shows in the sidebar.
3. **Encrypt** — upload an image, type a message and an AES key, click
   **Encrypt & Hide Message**, then **Download Stego Image**.
4. **Decrypt** — upload the downloaded stego image, enter the same AES key,
   click **Decrypt & Extract Message** to recover the original text.
5. Try a wrong key to see the clean rejection message.

### Example Test Case

- Message: `Hello, this is my secret message.`
- Key: `123456789`
- Expected recovered message: `Hello, this is my secret message.`
- Wrong key (`wrong-key`) → `Wrong AES key or invalid encrypted image.`
