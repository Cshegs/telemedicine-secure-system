"""
System Design page (/design).

This route exists to make the project's "Design" objective visible inside
the running application itself, not just in the written chapters. It
renders the six-step pipeline, the reasoning behind the three weighting
profiles, the three-layer architecture, and the doctor-to-patient data
flow, all from one structured source of data below.
"""

from fastapi import APIRouter, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_session_user

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# A) Six-step pipeline (mirrors app/crypto/hybrid_fusion.py exactly)
# ---------------------------------------------------------------------------

PIPELINE_STEPS = [
    {
        "num": 1,
        "title": "ECC X25519 Exchange",
        "formula": "K1 = dA . QB = dB . QA",
        "detail": (
            "Doctor and patient each generate an ephemeral X25519 keypair "
            "and swap public keys. Both sides land on the same shared "
            "secret K1 without ever sending K1 itself over the network."
        ),
        "color": "blue",
    },
    {
        "num": 2,
        "title": "ML-KEM (CRYSTALS-Kyber)",
        "formula": "Encaps(pk) -> (ciphertext, K2)",
        "detail": (
            "Real NIST FIPS 203 ML-KEM, via liboqs. One side encapsulates "
            "a second shared secret K2 against the other side's public "
            "key. This is the quantum-resistant half of the pair. Which "
            "parameter set runs here -- ML-KEM-512, -768, or -1024 -- is "
            "chosen per operation type in the next section."
        ),
        "color": "purple",
    },
    {
        "num": 3,
        "title": "SHA-256 Normalise",
        "formula": "K1\u2032 = H(K1),  K2\u2032 = H(K2)",
        "detail": (
            "Both raw secrets are hashed down to a uniform 32-byte form. "
            "This strips away any structure that came from the "
            "underlying algorithm, before the two are fused together."
        ),
        "color": "yellow",
    },
    {
        "num": 4,
        "title": "Full-Entropy Fusion",
        "formula": "Kf = SHA256(K1\u2032 \u2016 K2\u2032)",
        "detail": (
            "K1\u2032 and K2\u2032 are always combined in full -- no bytes are "
            "dropped from either side, so breaking one leg alone never "
            "weakens Kf below the other leg's full strength. The project's "
            "actual weighting decision already happened at Step 2: alpha "
            "and beta chose which ML-KEM parameter set (512/768/1024) got "
            "used, not how much of it survives fusion."
        ),
        "color": "orange",
    },
    {
        "num": 5,
        "title": "HKDF + Context",
        "formula": "Kfinal = HKDF(Kf \u2016 SID \u2016 T \u2016 PID)",
        "detail": (
            "The fused key is bound to a session ID, a timestamp, and a "
            "patient/context ID. The same Kf used twice would still "
            "produce two different final keys."
        ),
        "color": "teal",
    },
    {
        "num": 6,
        "title": "AES-256-GCM",
        "formula": "C = AES-GCM-Encrypt(Kfinal, plaintext)",
        "detail": (
            "Kfinal is the ready-to-use 256-bit AES key. It encrypts the "
            "record, chat message, or call payload with authenticated "
            "encryption."
        ),
        "color": "green",
    },
]


# ---------------------------------------------------------------------------
# B) Three weighting profiles and the reasoning behind each one
# ---------------------------------------------------------------------------

PROFILES = [
    {
        "name": "SPEED_PROFILE",
        "kem_alg": "ML-KEM-512",
        "use_case": "Video Call",
        "color": "sky",
        "heading": "Why speed matters here",
        "why": (
            "A video call needs a fresh session key the instant the call "
            "connects, so this profile pairs ECC with ML-KEM-512 -- NIST "
            "security category 1, the smallest and fastest standardised "
            "ML-KEM parameter set. Still fully quantum-resistant, just the "
            "lightest tier, and always combined at full strength with the "
            "ECC leg (Step 4 never drops bytes from either side)."
        ),
    },
    {
        "name": "BALANCED_PROFILE",
        "kem_alg": "ML-KEM-768",
        "use_case": "Secure Chat",
        "color": "violet",
        "heading": "Why this is the paper's optimal point",
        "why": (
            "Chat messages are frequent but not as time-critical as a live "
            "call, so this profile uses ML-KEM-768 -- NIST security "
            "category 3, and the parameter set most healthcare PQC "
            "guidance recommends as a general-purpose default. This is "
            "also the fixed algorithm the traditional baseline uses, so "
            "it's the fairest single point of comparison."
        ),
    },
    {
        "name": "SECURITY_PROFILE",
        "kem_alg": "ML-KEM-1024",
        "use_case": "Patient Records",
        "color": "emerald",
        "heading": "Why quantum resistance matters here",
        "why": (
            "Patient records are written once and may need to stay "
            "confidential for decades, well past the point a quantum "
            "computer could threaten classical ECC. This profile spends "
            "the extra key/ciphertext size of ML-KEM-1024 -- NIST security "
            "category 5, the strongest standardised parameter set -- as "
            "an acceptable bandwidth cost for the highest-sensitivity data."
        ),
    },
]


# ---------------------------------------------------------------------------
# C) Three-layer system architecture
# ---------------------------------------------------------------------------

ARCHITECTURE_LAYERS = [
    {
        "title": "Browser",
        "subtitle": "WebRTC + WebSocket",
        "detail": (
            "Doctor and patient connect from the browser. Video and audio "
            "run over WebRTC; chat runs over a WebSocket. No cryptography "
            "happens on the client; it only ever sees ciphertext and "
            "decrypted display text served to it."
        ),
        "color": "blue",
    },
    {
        "title": "FastAPI Server",
        "subtitle": "Hybrid ECC-Kyber Pipeline",
        "detail": (
            "Every operation calls establish_session_key(), which runs "
            "the full six-step pipeline server-side and returns a fresh "
            "Kfinal for that operation alone."
        ),
        "color": "indigo",
    },
    {
        "title": "SQLite",
        "subtitle": "Encrypted at rest",
        "detail": (
            "Only AES-256-GCM ciphertext and a wrapped form of Kfinal are "
            "stored. Plaintext and the raw Kfinal are never written to "
            "disk in any table."
        ),
        "color": "slate",
    },
]


# ---------------------------------------------------------------------------
# D) Patient-record data flow (doctor side -> server -> patient side)
# ---------------------------------------------------------------------------

DATA_FLOW_STEPS = [
    {"actor": "doctor",  "label": "Doctor inputs plaintext",        "detail": "a diagnosis or prescription note"},
    {"actor": "server",  "label": "establish_session_key()",        "detail": "SECURITY_PROFILE pipeline runs, returns Kfinal"},
    {"actor": "server",  "label": "AES-256-GCM encrypt",             "detail": "plaintext -> ciphertext + nonce"},
    {"actor": "server",  "label": "Store ciphertext + wrapped_key",  "detail": "Kfinal wrapped under the server master key"},
    {"actor": "patient", "label": "Patient requests record",         "detail": "opens /records"},
    {"actor": "server",  "label": "unwrap_key()",                   "detail": "recovers the original Kfinal"},
    {"actor": "server",  "label": "AES-256-GCM decrypt",             "detail": "ciphertext -> plaintext"},
    {"actor": "patient", "label": "Patient sees plaintext",          "detail": "decrypted in real time on page load"},
]


@router.get("/design")
async def design_page(request: Request, db: Session = Depends(get_db)):
    user = get_session_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)

    return templates.TemplateResponse(request, "design.html", {
        "user": user,
        "pipeline_steps": PIPELINE_STEPS,
        "profiles": PROFILES,
        "architecture_layers": ARCHITECTURE_LAYERS,
        "data_flow_steps": DATA_FLOW_STEPS,
    })
