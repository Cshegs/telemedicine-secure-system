from fastapi import APIRouter, Request, Depends, Form, Query
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_session_user
from app.models import User, PatientRecord
from app.crypto.hybrid_fusion import (
    establish_session_key, aes_encrypt, aes_decrypt, wrap_key, unwrap_key
)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

RECORD_TYPES = ["Diagnosis", "Prescription", "Lab Results", "Progress Note", "Referral"]


def _decrypt_record(rec: PatientRecord) -> str:
    """Unwraps kfinal from DB, then decrypts the record content."""
    try:
        kfinal = unwrap_key(rec.wrapped_key)
        return aes_decrypt(kfinal, rec.ciphertext, rec.nonce)
    except Exception:
        return "[Decryption error — key or ciphertext may be corrupt]"


# ---------------------------------------------------------------------------
# Doctor: list/add records for a specific patient
# Patient: view own records (read-only)
# ---------------------------------------------------------------------------

@router.get("/records")
async def records_page(
    request: Request,
    patient: int = Query(None),
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    if user.role == "doctor":
        # Must specify which patient via ?patient=<id>
        patients = db.query(User).filter_by(role="patient", assigned_doctor_id=user.id).all()

        selected_patient = None
        records = []
        if patient:
            selected_patient = db.get(User, patient)
            # Verify this patient belongs to the logged-in doctor
            if not selected_patient or selected_patient.assigned_doctor_id != user.id:
                selected_patient = None
            else:
                raw = (
                    db.query(PatientRecord)
                    .filter_by(patient_id=selected_patient.id)
                    .order_by(PatientRecord.created_at.desc())
                    .all()
                )
                records = [
                    {
                        "id": r.id,
                        "record_type": r.record_type,
                        "content": _decrypt_record(r),
                        "created_at": r.created_at,
                        "crypto_log": r.crypto_log,
                    }
                    for r in raw
                ]

        return templates.TemplateResponse(request, "records.html", {
            "user": user,
            "patients": patients,
            "selected_patient": selected_patient,
            "records": records,
            "record_types": RECORD_TYPES,
            "flash": request.query_params.get("flash"),
        })

    else:
        # Patient views their own records
        raw = (
            db.query(PatientRecord)
            .filter_by(patient_id=user.id)
            .order_by(PatientRecord.created_at.desc())
            .all()
        )
        records = [
            {
                "id": r.id,
                "record_type": r.record_type,
                "content": _decrypt_record(r),
                "created_at": r.created_at,
                "crypto_log": r.crypto_log,
            }
            for r in raw
        ]
        return templates.TemplateResponse(request, "records.html", {
            "user": user,
            "records": records,
        })


@router.post("/records")
async def create_record(
    request: Request,
    patient_id: int = Form(...),
    record_type: str = Form(...),
    content: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user or user.role != "doctor":
        return RedirectResponse("/login", status_code=302)

    # Verify the patient belongs to this doctor
    patient = db.get(User, patient_id)
    if not patient or patient.assigned_doctor_id != user.id:
        return RedirectResponse("/records", status_code=302)

    # Run the six-step pipeline with SECURITY_PROFILE (patient_record)
    result = establish_session_key("patient_record", str(patient_id), db=db)
    kfinal = result["kfinal"]

    # Encrypt the record content
    ciphertext_hex, nonce_hex = aes_encrypt(kfinal, content)

    # Wrap kfinal so we can recover it for future decryption
    wrapped = wrap_key(kfinal)

    rec = PatientRecord(
        patient_id=patient_id,
        doctor_id=user.id,
        record_type=record_type,
        ciphertext=ciphertext_hex,
        nonce=nonce_hex,
        wrapped_key=wrapped,
        crypto_log_id=result.get("log_id"),
    )
    db.add(rec)
    db.commit()

    return RedirectResponse(
        f"/records?patient={patient_id}&flash=Record+saved+and+encrypted",
        status_code=302,
    )
