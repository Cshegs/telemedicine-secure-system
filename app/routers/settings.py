from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_session_user

router = APIRouter(prefix="/settings")


@router.post("/encryption-mode")
async def set_encryption_mode(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    body = await request.json()
    mode = (body.get("mode") or "").strip().lower()
    if mode not in {"proposed", "traditional"}:
        raise HTTPException(status_code=400, detail="Invalid encryption mode")

    request.session["encryption_mode"] = mode
    return JSONResponse({"status": "ok", "mode": mode})

@router.get("/encryption-mode")
async def get_encryption_mode(request: Request):
    mode = request.session.get("encryption_mode", "proposed")
    return JSONResponse({"mode": mode})