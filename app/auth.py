import hashlib
import hmac
import os
from fastapi import Request
from sqlalchemy.orm import Session

# PBKDF2-SHA256 via stdlib — no passlib/bcrypt compatibility issues on Python 3.14.
# Format: "pbkdf2$<hex-salt>$<hex-hash>"
_ITERATIONS = 260_000
_HASH_ALG = "sha256"


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac(_HASH_ALG, password.encode(), salt, _ITERATIONS)
    return f"pbkdf2${salt.hex()}${h.hex()}"


def verify_password(plain: str, stored: str) -> bool:
    try:
        _, salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    actual = hashlib.pbkdf2_hmac(_HASH_ALG, plain.encode(), salt, _ITERATIONS)
    return hmac.compare_digest(actual, expected)


def get_session_user(request: Request, db: Session):
    """Returns the logged-in User or None."""
    from app.models import User
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)
