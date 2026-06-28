"""
Creates the demo accounts on every startup if they don't already exist.
Render's free tier has an ephemeral filesystem, so this re-seeds after
every cold start — the demo is always ready without manual setup.
"""
from app.database import SessionLocal
from app.models import User
from app.auth import hash_password

DEMO_PASSWORD = "demo1234"

DOCTORS = [
    {"username": "adaeze", "full_name": "Dr. Adaeze Nwosu"},
    {"username": "tunde",  "full_name": "Dr. Tunde Bakare"},
]

PATIENTS = [
    {"username": "amara",    "full_name": "Amara Okafor",   "doctor": "adaeze"},
    {"username": "chidinma", "full_name": "Chidinma Obi",   "doctor": "adaeze"},
    {"username": "bashir",   "full_name": "Bashir Lawal",   "doctor": "tunde"},
    {"username": "ngozi",    "full_name": "Ngozi Eze",      "doctor": "tunde"},
]


def _upsert_user(db, username: str, full_name: str, role: str) -> User:
    user = db.query(User).filter_by(username=username).first()
    if not user:
        user = User(
            username=username,
            password_hash=hash_password(DEMO_PASSWORD),
            full_name=full_name,
            role=role,
        )
        db.add(user)
        db.flush()  # get user.id before commit
    return user


def run_seed():
    db = SessionLocal()
    try:
        # Create doctors first so we have their IDs for patient assignment
        doctor_map: dict[str, User] = {}
        for d in DOCTORS:
            doctor_map[d["username"]] = _upsert_user(db, d["username"], d["full_name"], "doctor")

        for p in PATIENTS:
            patient = _upsert_user(db, p["username"], p["full_name"], "patient")
            # Assign to doctor only if not already assigned
            if patient.assigned_doctor_id is None:
                patient.assigned_doctor_id = doctor_map[p["doctor"]].id

        db.commit()
    finally:
        db.close()
