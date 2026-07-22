"""
Six-step hybrid ECC-Kyber key fusion pipeline.

Paper: "Design of a Context-Aware Hybrid ECC-Kyber Cryptographic Framework
with Secure Key Fusion for Telemedicine Information Security."

Pipeline (ported from paper_implementation.py):
  Step 1: ECC (X25519) key exchange             -> K1
  Step 2: CRYSTALS-Kyber key encapsulation      -> K2
  Step 3: Key normalisation (SHA-256)           -> K1', K2'
  Step 4: Weighted secure key fusion            -> Kf = SHA256(alpha*K1' || beta*K2')
  Step 5: Context-aware key derivation (HKDF)  -> Kfinal = HKDF(Kf || SID || T || PID)
  Step 6: AES-256-GCM encryption               -> C

MockKyber is a placeholder for real ML-KEM-768.
To swap in the real implementation:
  1. pip install liboqs-python
  2. Replace MockKyber with oqs.KeyEncapsulation("Kyber768")
     matching the same KeyGen / Encaps / Decaps API.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto.profiles import OPERATION_TYPE_TO_PROFILE


# ---------------------------------------------------------------------------
# MockKyber --same interface as real Kyber (KeyGen / Encaps / Decaps)
# ---------------------------------------------------------------------------

class MockKyber:
    """
    Stands in for real CRYSTALS-Kyber.
    Same three-function interface: KeyGen -> Encaps -> Decaps.
    NOT quantum-safe. For demonstrating the protocol structure only.
    Replace with liboqs-python for production/research use.
    """

    def KeyGen(self) -> tuple[bytes, bytes]:
        """Returns (public_key, secret_key)"""
        sk = os.urandom(32)
        pk = hashlib.sha256(b"kyber-pk" + sk).digest()
        return pk, sk

    def Encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_key K2)"""
        ephemeral = os.urandom(32)
        K2 = hashlib.sha256(b"kyber-K2" + ephemeral + pk).digest()
        ciphertext = ephemeral + hashlib.sha256(K2 + pk).digest()
        return ciphertext, K2

    def Decaps(self, ciphertext: bytes, sk: bytes) -> bytes:
        """Recovers shared_key K2 from ciphertext and secret key"""
        pk = hashlib.sha256(b"kyber-pk" + sk).digest()
        ephemeral = ciphertext[:32]
        return hashlib.sha256(b"kyber-K2" + ephemeral + pk).digest()


_kyber = MockKyber()


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def establish_session_key(
    operation_type: str,
    context_id: str,
    db=None,
) -> dict:
    """
    Runs the full six-step hybrid ECC-Kyber key fusion pipeline.

    Parameters
    ----------
    operation_type : "video_call" | "chat" | "patient_record"
    context_id     : patient_id or context string (used as PID in Step 5)
    db             : optional SQLAlchemy Session; if supplied, writes a
                     CryptoOperationLog row so the dashboard can query history

    Returns
    -------
    dict --see keys below; kfinal (bytes) is the ready-to-use AES-256 key
    """
    profile = OPERATION_TYPE_TO_PROFILE.get(operation_type)
    if profile is None:
        raise ValueError(
            f"Unknown operation_type '{operation_type}'. "
            f"Expected one of: {list(OPERATION_TYPE_TO_PROFILE.keys())}"
        )

    alpha: float = profile["alpha"]
    beta: float  = profile["beta"]

    t_start = time.perf_counter()

    # -- Step 1: ECC (X25519) key exchange -----------------------------------
    # Doctor (A) and Patient (B) each generate ephemeral keypairs.
    # K1 = dA * QB = dB * QA  (Diffie-Hellman on Curve25519)
    doctor_private  = X25519PrivateKey.generate()
    patient_private = X25519PrivateKey.generate()
    K1 = doctor_private.exchange(patient_private.public_key())

    # -- Step 2: Kyber key encapsulation -------------------------------------
    pk, sk = _kyber.KeyGen()
    ciphertext, K2 = _kyber.Encaps(pk)

    # -- Step 3: Key normalisation (SHA-256) ---------------------------------
    # K1' = H(K1),  K2' = H(K2)  -- uniform 256-bit output, no structure
    K1_norm = hashlib.sha256(K1).digest()
    K2_norm = hashlib.sha256(K2).digest()

    # -- Step 4: Weighted secure key fusion ----------------------------------
    # Take round(alpha*32) bytes from K1' and round(beta*32) bytes from K2'.
    # Kf = SHA256(alpha*K1' || beta*K2')
    bytes_from_k1 = max(1, round(alpha * 32))
    bytes_from_k2 = max(1, round(beta  * 32))
    Kf = hashlib.sha256(K1_norm[:bytes_from_k1] + K2_norm[:bytes_from_k2]).digest()

    # -- Step 5: Context-aware key derivation (HKDF) -------------------------
    # SID = session UUID,  T = ISO timestamp,  PID = patient/context ID
    SID = str(uuid.uuid4())
    T   = datetime.now(timezone.utc).isoformat()
    PID = str(context_id)

    # Kfinal = HKDF(Kf || SID || T || PID)
    Kc = (Kf + SID.encode() + T.encode() + PID.encode())
    Kfinal: bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"telemedicine-hybrid-ecc-kyber-v1",
    ).derive(Kc)

    t_end = time.perf_counter()
    execution_time_ms = round((t_end - t_start) * 1000, 3)

    result = {
        # The usable key --never logged or returned to the client
        "kfinal":            Kfinal,
        # Profile metadata
        "alpha":             alpha,
        "beta":              beta,
        "profile_name":      profile["name"],
        "operation_type":    operation_type,
        "context_id":        PID,
        # Key fusion accounting
        "bytes_from_k1":     bytes_from_k1,
        "bytes_from_k2":     bytes_from_k2,
        # Preview values (first 8 hex chars --safe to display)
        "k1_prime_preview":  K1_norm.hex()[:8],
        "k2_prime_preview":  K2_norm.hex()[:8],
        "kf_preview":        Kf.hex()[:8],
        "kfinal_preview":    Kfinal.hex()[:8],
        # Session context
        "sid":               SID,
        "timestamp":         T,
        "execution_time_ms": execution_time_ms,
        # Per-step details for the pipeline visualiser
        "step_details": {
            "step1": {
                "label":   "ECC X25519 Exchange → K1",
                "preview": K1.hex()[:16],
            },
            "step2": {
                "label":   "MockKyber Encapsulation → K2",
                "preview": K2.hex()[:16],
            },
            "step3": {
                "label":    "SHA-256 Normalisation → K1′, K2′",
                "k1_prime": K1_norm.hex()[:16],
                "k2_prime": K2_norm.hex()[:16],
            },
            "step4": {
                "label":         "Weighted Fusion → Kf",
                "preview":       Kf.hex()[:16],
                "bytes_from_k1": bytes_from_k1,
                "bytes_from_k2": bytes_from_k2,
            },
            "step5": {
                "label":   "HKDF Context Derivation → Kfinal",
                "preview": Kfinal.hex()[:16],
                "sid":     SID,
                "pid":     PID,
            },
            "step6": {
                "label":       "AES-256-GCM Ready",
                "key_preview": Kfinal.hex()[:8],
            },
        },
    }

    if db is not None:
        _write_log(db, result)

    return result


def _write_log(db, result: dict) -> None:
    """Inserts a CryptoOperationLog row. Non-fatal on failure."""
    from app.models import CryptoOperationLog
    try:
        log = CryptoOperationLog(
            operation_type=result["operation_type"],
            alpha=result["alpha"],
            beta=result["beta"],
            bytes_from_k1=result["bytes_from_k1"],
            bytes_from_k2=result["bytes_from_k2"],
            k1_prime_preview=result["k1_prime_preview"],
            k2_prime_preview=result["k2_prime_preview"],
            kf_preview=result["kf_preview"],
            sid=result["sid"],
            execution_time_ms=result["execution_time_ms"],
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        result["log_id"] = log.id
    except Exception:
        db.rollback()
        result["log_id"] = None


# ---------------------------------------------------------------------------
# AES-256-GCM helpers (used by records and chat routers)
# ---------------------------------------------------------------------------

def aes_encrypt(kfinal: bytes, plaintext: str) -> tuple[str, str]:
    """
    Encrypts plaintext with AES-256-GCM.
    Returns (ciphertext_hex, nonce_hex).
    """
    nonce = os.urandom(12)
    ct = AESGCM(kfinal).encrypt(nonce, plaintext.encode(), None)
    return ct.hex(), nonce.hex()


def aes_decrypt(kfinal: bytes, ciphertext_hex: str, nonce_hex: str) -> str:
    """
    Decrypts AES-256-GCM ciphertext. Raises on authentication failure.
    """
    ct    = bytes.fromhex(ciphertext_hex)
    nonce = bytes.fromhex(nonce_hex)
    return AESGCM(kfinal).decrypt(nonce, ct, None).decode()


# ---------------------------------------------------------------------------
# Key wrapping --stores kfinal securely alongside the encrypted record
# ---------------------------------------------------------------------------
# Because ECC and Kyber keys are ephemeral, kfinal changes on every call to
# establish_session_key().  To decrypt a stored record later we need the
# original kfinal.  We wrap (encrypt) it under a server master key derived
# from SESSION_SECRET via HKDF, then store the wrapped form in the DB.
# This is standard practice (RFC 3394 / AES key wrapping).  The master key
# is consistent across restarts as long as SESSION_SECRET doesn't change.

def _master_key() -> bytes:
    """Derives the server-side key-wrapping key from SESSION_SECRET."""
    import os as _os
    secret = _os.environ.get("SESSION_SECRET", "dev-secret-please-change-in-production").encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"telemed-record-wrapping-key-v1",
    ).derive(secret)


def wrap_key(kfinal: bytes) -> str:
    """
    Encrypts kfinal under the server master key.
    Returns a single string  "nonce_hex:ciphertext_hex"  for DB storage.
    """
    nonce = os.urandom(12)
    ct = AESGCM(_master_key()).encrypt(nonce, kfinal, None)
    return nonce.hex() + ":" + ct.hex()


def unwrap_key(wrapped: str) -> bytes:
    """
    Recovers kfinal from the wrapped string stored in the DB.
    Raises on authentication failure (tampered data).
    """
    nonce_hex, ct_hex = wrapped.split(":", 1)
    return AESGCM(_master_key()).decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)
