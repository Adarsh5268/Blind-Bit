# BlindBit

Live Demo: https://blindbit.pythonanywhere.com/

BlindBit is a Django web application that demonstrates Symmetric Searchable Encryption (SSE) for secure storage and search of encrypted files and records.

## What It Does

- Encrypts uploaded files and records using AES-GCM.
- Builds searchable encrypted indexes using HMAC-based tokens.
- Supports secure keyword search without exposing plaintext content.
- Includes 2FA-gated vault access and optional Google OAuth login.
- Supports file sharing with wrapped per-file keys.

## Tech Stack

- Backend: Django 5
- Database: SQLite (default)
- Crypto: `cryptography` (AES-GCM, HKDF, HMAC)
- Auth: Django auth, django-allauth, TOTP (`pyotp`)

## Project Structure

```text
Blind-Bit/
|- accounts/                 # Auth, 2FA, social auth adapters
|  |- migrations/
|  |- adapters.py
|  |- models.py
|  |- urls.py
|  |- views.py
|- blindbit_web/             # Django project config
|  |- settings.py
|  |- urls.py
|  |- wsgi.py
|  |- asgi.py
|  |- security_headers.py
|- drive/                    # Encrypted files/records, search, sharing
|  |- migrations/
|  |- models.py
|  |- sse_bridge.py
|  |- urls.py
|  |- views.py
|- client/                   # SSE client-side crypto helpers
|- server/                   # SSE server-side helper modules
|- templates/                # Django templates
|- static/                   # CSS, JS, icons
|- storage/                  # Runtime encrypted storage
|- docs/                     # Threat model, diagrams, deployment docs
|- manage.py
|- requirements.txt
|- app.sqlite3               # Default SQLite DB (dev/default)
|- .env                      # Environment variables (local/prod)
`- README.md
```

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies.
3. Create `.env`.
4. Run migrations.
5. Start the server.

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create `.env` in project root:

```dotenv
DJANGO_SECRET_KEY=replace-with-a-strong-random-secret
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
DJANGO_DB_PATH=app.sqlite3
SEARCH_OBFUSCATION_ENABLED=True
SEARCH_OBFUSCATION_DECOYS=2
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
```

Run app:

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open: `http://127.0.0.1:8000/`

## Useful Commands

```bash
python manage.py check
python manage.py test accounts drive
python manage.py collectstatic --noinput
```

## Deployment (PythonAnywhere, Direct Upload)

Use this guide:

- `docs/PYTHONANYWHERE_DIRECT_UPLOAD_DEPLOYMENT.md`

## Google OAuth Redirect URI

If Google sign-in is enabled, add this exact redirect URI in Google Cloud Console:

- `https://<your-username>.pythonanywhere.com/accounts/google/login/callback/`

Use `https` and keep the trailing slash.

## Security Notes

- Keep `DJANGO_DEBUG=False` in production.
- Rotate secrets immediately if exposed.
- Back up `app.sqlite3`, `media/`, and `storage/`.

## License

MIT License
