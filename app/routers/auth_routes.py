from fastapi import APIRouter, Request, Depends, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, PatientRecord, ChatMessage, CryptoOperationLog
from app.auth import verify_password, get_session_user

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Shown on the login page so examiners can log in without any setup
DEMO_CREDENTIALS = [
    {"role": "Doctor",  "username": "adaeze",   "name": "Dr. Adaeze Nwosu"},
    {"role": "Doctor",  "username": "tunde",    "name": "Dr. Tunde Bakare"},
    {"role": "Patient", "username": "amara",    "name": "Amara Okafor"},
    {"role": "Patient", "username": "chidinma", "name": "Chidinma Obi"},
    {"role": "Patient", "username": "bashir",   "name": "Bashir Lawal"},
    {"role": "Patient", "username": "ngozi",    "name": "Ngozi Eze"},
]


@router.get("/login")
async def login_page(request: Request, db: Session = Depends(get_db)):
    if get_session_user(request, db):
        return RedirectResponse("/dashboard", status_code=302)
    return templates.TemplateResponse(request, "login.html", {
        "user": None,
        "demo": DEMO_CREDENTIALS,
        "error": None,
    })


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(username=username).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(request, "login.html", {
            "user": None,
            "demo": DEMO_CREDENTIALS,
            "error": "Incorrect username or password.",
        })
    request.session["user_id"] = user.id
    return RedirectResponse("/dashboard", status_code=302)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@router.get("/dashboard")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    if user.role == "doctor":
        patients = db.query(User).filter_by(role="patient", assigned_doctor_id=user.id).all()
        patient_ids = [p.id for p in patients]
        record_count = (
            db.query(PatientRecord).filter(PatientRecord.patient_id.in_(patient_ids)).count()
            if patient_ids else 0
        )
        msg_count = (
            db.query(ChatMessage).filter(
                (ChatMessage.sender_id == user.id) | (ChatMessage.receiver_id == user.id)
            ).count()
        )
        crypto_count = db.query(CryptoOperationLog).count()
        return templates.TemplateResponse(request, "dashboard.html", {
            "user": user,
            "patients": patients,
            "record_count": record_count,
            "msg_count": msg_count,
            "crypto_count": crypto_count,
        })
    else:
        doctor = db.get(User, user.assigned_doctor_id) if user.assigned_doctor_id else None
        record_count = db.query(PatientRecord).filter_by(patient_id=user.id).count()
        return templates.TemplateResponse(request, "dashboard.html", {
            "user": user,
            "doctor": doctor,
            "record_count": record_count,
        })
