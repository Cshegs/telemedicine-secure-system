"""
Phase 4 — Real-time encrypted chat.

Each message:
  1. Arrives via WebSocket (plaintext from the sender's browser)
  2. establish_session_key("chat", patient_id) → kfinal  [BALANCED_PROFILE α=0.4 β=0.6]
  3. AES-256-GCM encrypt → stored in DB (ciphertext + nonce + wrapped_key)
  4. Plaintext + metadata broadcast to all connected sockets in the room

History load (GET /chat):
  - All past messages for the pair are fetched from DB, unwrapped + decrypted server-side,
    and sent to the template as plain dicts.  Plaintext never persisted.

WebSocket auth:
  - Starlette's SessionMiddleware populates scope["session"] for WebSocket connections
    the same way it does for HTTP — we read user_id from there.
"""

import json
from datetime import datetime, timezone
from typing import DefaultDict
from collections import defaultdict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, Depends, Query, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.requests import Request as StarletteRequest

from app.database import SessionLocal, get_db
from app.auth import get_session_user
from app.models import User, ChatMessage
from app.crypto.hybrid_fusion import (
    establish_session_key, aes_encrypt, aes_decrypt, wrap_key, unwrap_key
)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# In-memory room registry: room_key -> set of WebSocket connections
_rooms: DefaultDict[str, set] = defaultdict(set)


def _room_key(id_a: int, id_b: int) -> str:
    """Stable room key regardless of who initiates."""
    return f"{min(id_a, id_b)}_{max(id_a, id_b)}"


def _patient_id_for_pair(user_a: User, user_b: User) -> int:
    """Returns the patient's id from a doctor-patient pair."""
    return user_a.id if user_a.role == "patient" else user_b.id


def _decrypt_msg(msg: ChatMessage) -> str:
    try:
        kfinal = unwrap_key(msg.wrapped_key)
        return aes_decrypt(kfinal, msg.ciphertext, msg.nonce)
    except Exception:
        return "[decryption error]"


def _other_user(db: Session, current_user: User, other_id: int) -> User | None:
    """Fetch the other party and validate the doctor-patient relationship."""
    other = db.get(User, other_id)
    if not other:
        return None
    ids = {current_user.id, other.id}
    # One must be doctor, one patient, and patient must be assigned to doctor
    if current_user.role == "doctor" and other.role == "patient":
        return other if other.assigned_doctor_id == current_user.id else None
    if current_user.role == "patient" and other.role == "doctor":
        return other if current_user.assigned_doctor_id == other.id else None
    return None


def _current_mode(request: Request) -> str:
    return (request.session.get("encryption_mode", "proposed") or "proposed").lower()


async def _broadcast_chat_payload(room: str, payload: dict) -> None:
    """Broadcast a JSON payload to all live sockets in the room."""
    if room not in _rooms:
        return

    message = json.dumps(payload)
    dead = set()
    for ws in list(_rooms[room]):
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    _rooms[room] -= dead
    if not _rooms[room]:
        del _rooms[room]


def _chat_crypto_response(result: dict, ciphertext_hex: str) -> dict:
    """Shape the crypto metadata returned to the chat client."""
    return {
        "operation_type": result["operation_type"],
        "profile_name": result["profile_name"],
        "alpha": result["alpha"],
        "beta": result["beta"],
        "sid": result["sid"],
        "execution_time_ms": result["execution_time_ms"],
        "kf_preview": result["kf_preview"],
        "ciphertext_hex": ciphertext_hex[:32],
    }


async def _save_chat_message(request: Request, db: Session, user: User, other: User, text: str) -> dict:
    """Encrypt, persist, and broadcast a chat message, then return crypto metadata."""
    patient_id = _patient_id_for_pair(user, other)

    result = establish_session_key("chat", str(patient_id), db=db, mode=_current_mode(request))
    kfinal = result["kfinal"]

    ct_hex, nonce_hex = aes_encrypt(kfinal, text)
    wrapped = wrap_key(kfinal)

    msg = ChatMessage(
        sender_id=user.id,
        receiver_id=other.id,
        ciphertext=ct_hex,
        nonce=nonce_hex,
        wrapped_key=wrapped,
        crypto_log_id=result.get("log_id"),
    )
    db.add(msg)
    db.commit()

    payload = {
        "sender_id": user.id,
        "sender_name": user.full_name,
        "text": text,
        "timestamp": datetime.now(timezone.utc).strftime("%H:%M"),
        "exec_ms": result["execution_time_ms"],
        "alpha": result["alpha"],
        "beta": result["beta"],
        "kf_preview": result["kf_preview"],
    }
    await _broadcast_chat_payload(_room_key(user.id, other.id), payload)

    return _chat_crypto_response(result, ct_hex)


# ---------------------------------------------------------------------------
# HTTP — chat page with history
# ---------------------------------------------------------------------------

@router.get("/chat")
async def chat_page(
    request: Request,
    with_: int = Query(None, alias="with"),
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Build conversation list (contacts)
    if user.role == "doctor":
        contacts = db.query(User).filter_by(role="patient", assigned_doctor_id=user.id).all()
    else:
        doc = db.get(User, user.assigned_doctor_id) if user.assigned_doctor_id else None
        contacts = [doc] if doc else []

    other = None
    history = []

    if with_ and contacts:
        other = _other_user(db, user, with_)
        if other:
            rows = (
                db.query(ChatMessage)
                .filter(
                    ((ChatMessage.sender_id == user.id) & (ChatMessage.receiver_id == other.id))
                    | ((ChatMessage.sender_id == other.id) & (ChatMessage.receiver_id == user.id))
                )
                .order_by(ChatMessage.created_at.asc())
                .all()
            )
            history = [
                {
                    "sender_id":   m.sender_id,
                    "sender_name": m.sender.full_name,
                    "text":        _decrypt_msg(m),
                    "timestamp":   m.created_at.strftime("%H:%M") if m.created_at else "",
                    "exec_ms":     m.crypto_log.execution_time_ms if m.crypto_log else None,
                }
                for m in rows
            ]

    return templates.TemplateResponse(request, "chat.html", {
        "user":     user,
        "contacts": contacts,
        "other":    other,
        "history":  history,
    })


# ---------------------------------------------------------------------------
# HTTP — save chat message from the client
# ---------------------------------------------------------------------------

@router.post("/chat/messages")
async def send_chat_message(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    data = await request.json()
    other_id = data.get("other_id")
    text = (data.get("text") or "").strip()

    if not other_id or not text:
        raise HTTPException(status_code=400, detail="Missing chat recipient or text")

    other = _other_user(db, user, int(other_id))
    if not other:
        raise HTTPException(status_code=403, detail="Invalid chat recipient")

    return await _save_chat_message(request, db, user, other, text)


# ---------------------------------------------------------------------------
# WebSocket — real-time messaging
# ---------------------------------------------------------------------------

@router.websocket("/ws/chat/{other_id}")
async def chat_ws(websocket: WebSocket, other_id: int):
    # Auth via starlette session scope (populated by SessionMiddleware for WS too)
    session = websocket.scope.get("session", {})
    user_id = session.get("user_id")
    if not user_id:
        await websocket.close(code=4001)
        return

    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        other = user and _other_user(db, user, other_id)
        if not user or not other:
            await websocket.close(code=4003)
            return

        room = _room_key(user.id, other.id)

        await websocket.accept()
        _rooms[room].add(websocket)

        try:
            while True:
                text = await websocket.receive_text()
                text = text.strip()
                if not text:
                    continue

                await _save_chat_message(db, user, other, text)

        except WebSocketDisconnect:
            pass
        finally:
            _rooms[room].discard(websocket)
            if not _rooms[room]:
                del _rooms[room]
    finally:
        db.close()
