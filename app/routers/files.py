import os
from uuid import uuid4
from fastapi import APIRouter, Request, Depends, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_session_user
from app.models import User, PatientFile
from app.storage import upload_encrypted_file, download_encrypted_file, delete_file
from app.crypto.hybrid_fusion import establish_session_key, wrap_key, unwrap_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

router = APIRouter()


def _current_mode(request: Request) -> str:
    return (request.session.get("encryption_mode", "proposed") or "proposed").lower()


@router.post("/files/upload")
async def upload_file(
    request: Request,
    patient_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload and encrypt a file for a patient."""
    user = get_session_user(request, db)
    if not user or user.role != "doctor":
        raise HTTPException(status_code=403, detail="Only doctors can upload files")
    
    # Verify the patient belongs to this doctor
    patient = db.get(User, patient_id)
    if not patient or patient.assigned_doctor_id != user.id:
        raise HTTPException(status_code=403, detail="Patient not assigned to this doctor")
    
    # Read file bytes
    file_bytes = await file.read()
    
    # Establish session key for this patient
    result = establish_session_key("patient_record", str(patient_id), db=db, mode=_current_mode(request))
    kfinal = result["kfinal"]
    
    # Generate nonce and encrypt file bytes
    nonce = os.urandom(12)
    encrypted_bytes = AESGCM(kfinal).encrypt(nonce, file_bytes, None)
    
    # Generate storage path
    filename = file.filename or "file"
    storage_path = f"patient_{patient_id}/{uuid4()}_{filename}"
    
    # Upload to Supabase Storage
    upload_encrypted_file(encrypted_bytes, storage_path, file.content_type or "application/octet-stream")
    
    # Store kfinal as hex for later decryption
    kfinal_hex = kfinal.hex()
    
    # Save record to database
    patient_file = PatientFile(
        patient_id=patient_id,
        doctor_id=user.id,
        original_filename=filename,
        file_type=file.content_type or "application/octet-stream",
        storage_path=storage_path,
        nonce=nonce.hex(),
        kfinal_hex=kfinal_hex,
        file_size_bytes=len(file_bytes),
        crypto_log_id=result.get("log_id"),
    )
    db.add(patient_file)
    db.commit()
    db.refresh(patient_file)
    
    return {
        "id": patient_file.id,
        "filename": filename,
        "storage_path": storage_path,
        "file_size_bytes": len(file_bytes),
    }


@router.get("/files/patient/{patient_id}")
async def list_patient_files(
    request: Request,
    patient_id: int,
    db: Session = Depends(get_db),
):
    """Get list of files for a patient."""
    user = get_session_user(request, db)
    if not user:
        raise HTTPException(status_code=403, detail="Not authenticated")
    
    # Check access: doctor sees all their patients' files, patient only sees own
    if user.role == "patient":
        if user.id != patient_id:
            raise HTTPException(status_code=403, detail="Can only view own files")
    else:  # doctor
        patient = db.get(User, patient_id)
        if not patient or patient.assigned_doctor_id != user.id:
            raise HTTPException(status_code=403, detail="Patient not assigned to this doctor")
    
    files = (
        db.query(PatientFile)
        .filter_by(patient_id=patient_id)
        .order_by(PatientFile.created_at.desc())
        .all()
    )
    
    return [
        {
            "id": f.id,
            "original_filename": f.original_filename,
            "file_type": f.file_type,
            "file_size_bytes": f.file_size_bytes,
            "created_at": f.created_at,
            "crypto_log": f.crypto_log,
        }
        for f in files
    ]


@router.get("/files/download/{file_id}")
async def download_file(
    request: Request,
    file_id: int,
    db: Session = Depends(get_db),
):
    """Download and decrypt a file."""
    user = get_session_user(request, db)
    if not user:
        raise HTTPException(status_code=403, detail="Not authenticated")
    
    patient_file = db.get(PatientFile, file_id)
    if not patient_file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Check access: patient or assigned doctor
    if user.role == "patient":
        if user.id != patient_file.patient_id:
            raise HTTPException(status_code=403, detail="Can only download own files")
    else:  # doctor
        if user.id != patient_file.doctor_id:
            raise HTTPException(status_code=403, detail="Can only download files you uploaded")
    
    # Download encrypted bytes from Supabase Storage
    encrypted_bytes = download_encrypted_file(patient_file.storage_path)
    
    # Decrypt using stored kfinal
    kfinal = bytes.fromhex(patient_file.kfinal_hex)
    nonce = bytes.fromhex(patient_file.nonce)
    decrypted_bytes = AESGCM(kfinal).decrypt(nonce, encrypted_bytes, None)
    
    # Return as attachment
    return Response(
        content=decrypted_bytes,
        media_type=patient_file.file_type,
        headers={"Content-Disposition": f'attachment; filename="{patient_file.original_filename}"'},
    )


@router.delete("/files/{file_id}")
async def delete_file_endpoint(
    request: Request,
    file_id: int,
    db: Session = Depends(get_db),
):
    """Delete a file (doctor only)."""
    user = get_session_user(request, db)
    if not user or user.role != "doctor":
        raise HTTPException(status_code=403, detail="Only doctors can delete files")
    
    patient_file = db.get(PatientFile, file_id)
    if not patient_file:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Verify this doctor uploaded the file
    if user.id != patient_file.doctor_id:
        raise HTTPException(status_code=403, detail="Can only delete files you uploaded")
    
    # Delete from Supabase Storage
    delete_file(patient_file.storage_path)
    
    # Delete from database
    db.delete(patient_file)
    db.commit()
    
    return {"message": "File deleted successfully"}
