"""
Jitsi Meet room-based calling with hybrid session key establishment.

The hybrid framework secures the call session record before the room is
joined. The browser then connects to a Jitsi room for real audio/video.
"""

import json
import uuid
from urllib.parse import urlencode
from datetime import datetime, timezone
from collections import defaultdict
from typing import DefaultDict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, Depends, Query
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_db
from app.auth import get_session_user
from app.models import User, CallSession
from app.crypto.hybrid_fusion import establish_session_key

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Signaling rooms: room_key -> list of (websocket, user_id)
_signal_rooms: DefaultDict[str, list] = defaultdict(list)


def _room_key(id_a: int, id_b: int) -> str:
    return f"{min(id_a, id_b)}_{max(id_a, id_b)}"


def _validate_pair(db: Session, user: User, other_id: int) -> User | None:
    """Return the other user if they form a valid doctor-patient pair."""
    other = db.get(User, other_id)
    if not other:
        return None
    if user.role == "doctor" and other.role == "patient":
        return other if other.assigned_doctor_id == user.id else None
    if user.role == "patient" and other.role == "doctor":
        return other if user.assigned_doctor_id == other.id else None
    return None


def _patient_id(user: User, other: User) -> int:
    return user.id if user.role == "patient" else other.id


def _doctor_id(user: User, other: User) -> int:
    return user.id if user.role == "doctor" else other.id


# ---------------------------------------------------------------------------
# HTTP — call page
# ---------------------------------------------------------------------------

@router.get("/call")
async def call_page(
    request: Request,
    room_url: str | None = Query(None),
    call_session_id: int | None = Query(None),
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Build contact list based on role
    if user.role == "doctor":
        contacts = db.query(User).filter_by(role="patient", assigned_doctor_id=user.id).all()
    else:
        doc = db.get(User, user.assigned_doctor_id) if user.assigned_doctor_id else None
        contacts = [doc] if doc else []

    # Recent call history
    call_history = (
        db.query(CallSession)
        .filter(
            (CallSession.doctor_id == (user.id if user.role == "doctor" else None)) |
            (CallSession.patient_id == (user.id if user.role == "patient" else None))
        )
        .order_by(CallSession.started_at.desc())
        .limit(10)
        .all()
    ) if user.role in ("doctor", "patient") else []

    # Simpler query covering both roles
    if user.role == "doctor":
        call_history = (
            db.query(CallSession)
            .filter_by(doctor_id=user.id)
            .order_by(CallSession.started_at.desc())
            .limit(10)
            .all()
        )
    else:
        call_history = (
            db.query(CallSession)
            .filter_by(patient_id=user.id)
            .order_by(CallSession.started_at.desc())
            .limit(10)
            .all()
        )

    return templates.TemplateResponse(request, "call.html", {
        "user":         user,
        "contacts":     contacts,
        "call_history": call_history,
        "room_url":     room_url,
        "call_session_id": call_session_id,
    })


# ---------------------------------------------------------------------------
# API — establish session key before Jitsi room creation
# ---------------------------------------------------------------------------

@router.post("/call/create-room")
async def create_call_room(
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    if user.role != "doctor":
        return JSONResponse({"error": "Only doctors can start calls"}, status_code=403)

    body = await request.json()
    patient_id = int(body.get("patient_id", 0))
    voice_only = bool(body.get("voice_only", False))

    other_id = patient_id
    other = _validate_pair(db, user, other_id)
    if not other:
        return JSONResponse({"error": "Invalid call target"}, status_code=400)

    pid = _patient_id(user, other)
    did = _doctor_id(user, other)

    # Run the hybrid pipeline before room creation so the timing is visible.
    result = establish_session_key("video_call", str(pid), db=db)

    room_name = uuid.uuid4().hex[:12]
    room_url = f"https://meet.jit.si/telemed-{room_name}"

    # Open a CallSession row (ended_at filled in by /call/end)
    session = CallSession(
        doctor_id=did,
        patient_id=pid,
        crypto_log_id=result.get("log_id"),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    join_url = f"{str(request.base_url).rstrip('/')}/call?{urlencode({'room_url': room_url, 'call_session_id': session.id})}"

    return JSONResponse({
        "call_session_id": session.id,
        "room_name": f"telemed-{room_name}",
        "room_url": room_url,
        "join_url": join_url,
        "voice_only": voice_only,
        "crypto": {
            "execution_time_ms": result["execution_time_ms"],
            "alpha": result["alpha"],
            "beta": result["beta"],
            "profile_name": result["profile_name"],
            "kf_preview": result["kf_preview"],
            "kfinal_preview": result["kfinal_preview"],
            "sid": result["sid"],
        },
    })


@router.post("/call/end")
async def end_call_session(
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    body = await request.json()
    session_id = int(body.get("call_session_id", 0))
    session = db.get(CallSession, session_id)
    if session and not session.ended_at:
        session.ended_at = datetime.now(timezone.utc)
        db.commit()

    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# WebSocket — signaling relay
# ---------------------------------------------------------------------------

@router.websocket("/ws/call/{other_id}")
async def call_signal_ws(websocket: WebSocket, other_id: int):
    session_scope = websocket.scope.get("session", {})
    user_id = session_scope.get("user_id")
    if not user_id:
        await websocket.close(code=4001)
        return

    db = SessionLocal()
    try:
        user = db.get(User, user_id)
        other = user and _validate_pair(db, user, other_id)
        if not user or not other:
            await websocket.close(code=4003)
            return

        room = _room_key(user.id, other.id)
        await websocket.accept()
        _signal_rooms[room].append((websocket, user.id))

        # Tell the new peer how many are in the room (used by JS to decide offerer/answerer)
        await websocket.send_text(json.dumps({
            "type":       "room-info",
            "peer_count": len(_signal_rooms[room]),
            "your_id":    user.id,
            "other_name": other.full_name,
        }))

        try:
            while True:
                raw = await websocket.receive_text()
                msg = json.loads(raw)

                # Relay to every OTHER socket in the room
                dead = []
                for (ws, uid) in list(_signal_rooms[room]):
                    if ws is websocket:
                        continue
                    try:
                        await ws.send_text(raw)
                    except Exception:
                        dead.append((ws, uid))

                for entry in dead:
                    _signal_rooms[room].remove(entry)

        except WebSocketDisconnect:
            pass
        finally:
            entry = (websocket, user.id)
            if entry in _signal_rooms[room]:
                _signal_rooms[room].remove(entry)
            if not _signal_rooms[room]:
                del _signal_rooms[room]
    finally:
        db.close()
