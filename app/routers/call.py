"""
Phase 5 — WebRTC video calling with hybrid session key establishment.

What the hybrid framework secures here:
  - The CALL SESSION RECORD (who called whom, when) is encrypted via the
    SPEED_PROFILE pipeline BEFORE the WebRTC handshake begins.
  - The live audio/video stream is encrypted natively by WebRTC using
    DTLS-SRTP — this happens automatically in the browser and is not
    replaced by this prototype (doing so would require a media server).

What this demonstrates:
  - Speed-priority key fusion (alpha=0.7, beta=0.3) is appropriate for
    live calls because session key setup must complete before the call
    connects.  The timing is shown to the user during the "Establishing
    secure session..." phase, making the trade-off from Table I visible.

Flow:
  1. Caller opens /call?with=<other_id>
  2. Clicks "Start Secure Call" → POST /call/start-session
     Server runs establish_session_key("video_call", patient_id),
     creates CallSession row, returns timing data.
  3. JS displays "Session established in X ms" for 2s, then begins WebRTC.
  4. Signaling: both peers connect to ws://host/ws/call/<other_id>.
     Server relays offer / answer / candidate / hangup messages.
  5. On hangup → POST /call/end → server records ended_at on CallSession.
"""

import json
from datetime import datetime, timezone
from collections import defaultdict
from typing import DefaultDict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, Depends
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
    })


# ---------------------------------------------------------------------------
# API — establish session key before WebRTC handshake
# ---------------------------------------------------------------------------

@router.post("/call/start-session")
async def start_call_session(
    request: Request,
    db: Session = Depends(get_db),
):
    user = get_session_user(request, db)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    body = await request.json()
    other_id = int(body.get("other_id", 0))
    other = _validate_pair(db, user, other_id)
    if not other:
        return JSONResponse({"error": "Invalid call target"}, status_code=400)

    pid = _patient_id(user, other)
    did = _doctor_id(user, other)

    # Run six-step pipeline with SPEED_PROFILE — must complete before call starts
    result = establish_session_key("video_call", str(pid), db=db)

    # Open a CallSession row (ended_at filled in by /call/end)
    session = CallSession(
        doctor_id=did,
        patient_id=pid,
        crypto_log_id=result.get("log_id"),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    return JSONResponse({
        "call_session_id":  session.id,
        "execution_time_ms": result["execution_time_ms"],
        "alpha":            result["alpha"],
        "beta":             result["beta"],
        "profile_name":     result["profile_name"],
        "kf_preview":       result["kf_preview"],
        "kfinal_preview":   result["kfinal_preview"],
        "sid":              result["sid"],
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
