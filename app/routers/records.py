import json

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

STRUCTURED_TESTS = {
    "blood_pressure": {
        "label": "Blood Pressure",
        "fields": [
            {"name": "date", "label": "Date of test", "type": "date"},
            {"name": "systolic", "label": "Systolic pressure", "type": "number", "unit": "mmHg", "step": "1"},
            {"name": "diastolic", "label": "Diastolic pressure", "type": "number", "unit": "mmHg", "step": "1"},
            {"name": "pulse", "label": "Pulse", "type": "number", "unit": "bpm", "step": "1"},
            {
                "name": "position",
                "label": "Patient position",
                "type": "select",
                "options": ["Sitting", "Standing", "Lying down"],
            },
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "blood_glucose": {
        "label": "Blood Glucose",
        "fields": [
            {"name": "date", "label": "Date of test", "type": "date"},
            {
                "name": "timing",
                "label": "Test timing",
                "type": "select",
                "options": ["Fasting", "2-hour post-meal", "Random"],
            },
            {"name": "glucose_value", "label": "Glucose value", "type": "number", "step": "0.1"},
            {"name": "unit", "label": "Unit", "type": "select", "options": ["mg/dL", "mmol/L"]},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "temperature": {
        "label": "Temperature",
        "fields": [
            {"name": "date", "label": "Date of test", "type": "date"},
            {"name": "temperature_value", "label": "Temperature value", "type": "number", "step": "0.1"},
            {"name": "unit", "label": "Unit", "type": "select", "options": ["C", "F"]},
            {
                "name": "method",
                "label": "Method",
                "type": "select",
                "options": ["Oral", "Axillary", "Rectal", "Ear"],
            },
        ],
    },
    "oxygen_saturation": {
        "label": "Oxygen Saturation (SpO2)",
        "fields": [
            {"name": "date", "label": "Date of test", "type": "date"},
            {"name": "spo2", "label": "SpO2 %", "type": "number", "min": "0", "max": "100", "step": "1"},
            {"name": "pulse_rate", "label": "Pulse rate", "type": "number", "unit": "bpm", "step": "1"},
            {"name": "notes", "label": "Notes", "type": "textarea"},
        ],
    },
    "bmi_assessment": {
        "label": "BMI Assessment",
        "fields": [
            {"name": "date", "label": "Date of test", "type": "date"},
            {"name": "weight", "label": "Weight", "type": "number", "step": "0.1"},
            {"name": "height", "label": "Height", "type": "number", "step": "0.1"},
            {
                "name": "unit_system",
                "label": "Unit system",
                "type": "select",
                "options": ["Metric kg/cm", "Imperial lb/ft"],
                "values": ["metric", "imperial"],
            },
            {"name": "bmi", "label": "Calculated BMI", "type": "number", "readonly": True, "step": "0.1"},
        ],
    },
    "lipid_panel": {
        "label": "Lipid Panel",
        "fields": [
            {"name": "date", "label": "Date of test", "type": "date"},
            {"name": "total_cholesterol", "label": "Total Cholesterol", "type": "number", "step": "0.1"},
            {"name": "hdl", "label": "HDL", "type": "number", "step": "0.1"},
            {"name": "ldl", "label": "LDL", "type": "number", "step": "0.1"},
            {"name": "triglycerides", "label": "Triglycerides", "type": "number", "step": "0.1"},
            {"name": "unit", "label": "Unit", "type": "select", "options": ["mg/dL", "mmol/L"]},
        ],
    },
}


def _structured_label(test_type: str) -> str | None:
    spec = STRUCTURED_TESTS.get(test_type)
    return spec["label"] if spec else None


def _parse_structured_record(content: str) -> dict | None:
    try:
        payload = json.loads(content)
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    test_type = payload.get("test_type")
    if test_type not in STRUCTURED_TESTS:
        return None

    spec = STRUCTURED_TESTS[test_type]
    display_fields = []
    for field in spec["fields"]:
        name = field["name"]
        if name not in payload:
            continue

        value = payload.get(name)
        if value in (None, ""):
            continue

        if field.get("type") == "select" and "options" in field:
            options = field["options"]
            values = field.get("values", options)
            try:
                option_index = values.index(value)
                value = options[option_index]
            except ValueError:
                pass

        display_fields.append({
            "label": field["label"],
            "value": value,
            "unit": field.get("unit"),
            "name": name,
            "readonly": field.get("readonly", False),
        })

    return {
        "test_type": test_type,
        "title": spec["label"],
        "fields": display_fields,
    }


def _decrypt_record(rec: PatientRecord) -> str:
    """Unwraps kfinal from DB, then decrypts the record content."""
    try:
        kfinal = unwrap_key(rec.wrapped_key)
        return aes_decrypt(kfinal, rec.ciphertext, rec.nonce)
    except Exception:
        return "[Decryption error --key or ciphertext may be corrupt]"


def _load_record_view(rec: PatientRecord) -> dict:
    content = _decrypt_record(rec)
    return {
        "id": rec.id,
        "record_type": rec.record_type,
        "content": content,
        "structured_content": _parse_structured_record(content),
        "created_at": rec.created_at,
        "crypto_log": rec.crypto_log,
    }


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
                    _load_record_view(r)
                    for r in raw
                ]

        return templates.TemplateResponse(request, "records.html", {
            "user": user,
            "patients": patients,
            "selected_patient": selected_patient,
            "records": records,
            "record_types": RECORD_TYPES,
            "structured_tests": STRUCTURED_TESTS,
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
            _load_record_view(r)
            for r in raw
        ]
        return templates.TemplateResponse(request, "records.html", {
            "user": user,
            "records": records,
            "structured_tests": STRUCTURED_TESTS,
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
