"""
Six-step hybrid ECC-Kyber key fusion pipeline.

Paper: "Design of a Context-Aware Hybrid ECC-Kyber Cryptographic Framework
with Secure Key Fusion for Telemedicine Information Security."

Pipeline:
  Step 1: ECC (X25519) key exchange              -> K1
  Step 2: ML-KEM key encapsulation (512/768/1024, profile-selected) -> K2
  Step 3: Key normalisation (SHA-256)             -> K1', K2'
  Step 4: Secure key fusion (full entropy)        -> Kf = SHA256(K1' || K2')
  Step 5: Context-aware key derivation (HKDF)     -> Kfinal = HKDF(Kf || SID || T || PID, info=profile)
  Step 6: AES-256-GCM encryption                  -> C

REVISION HISTORY (see CHANGES.md for the full writeup):

v1 used a placeholder ("MockKyber", a SHA-256 construction) instead of
real Kyber, and Step 4 truncated each normalised secret to
round(alpha*32) / round(beta*32) bytes before hashing them together
(e.g. SECURITY_PROFILE kept only 6 bytes / 48 bits of K1'). A peer
reviewer identified both issues: the truncation meant every profile was
*weaker* than a naive 50:50 concatenation baseline, because breaking
either leg reduced the other leg's effective search space below 256
bits; and the paper described CRYSTALS-Kyber/ML-KEM as implemented and
benchmarked when no such implementation existed in the codebase.

v2 fixed both: Kyber became real ML-KEM-768 via liboqs-python, and Step 4
started always combining the FULL 32 bytes of both K1' and K2' (no
truncation). alpha/beta then only selected an HKDF domain-separation
label -- a real but purely presentational property, since the combiner
itself no longer varied per profile.

v3 (this file) gives alpha/beta a security-relevant job again, without
reintroducing the truncation flaw: each profile now selects a different
NIST-standardised ML-KEM parameter set (512 / 768 / 1024) at Step 2,
trading key/ciphertext size and computation cost for security margin.
Step 4 is untouched -- it always uses 100% of whichever keys were
generated, for every profile, so this cannot reduce security below any
single parameter set's own guarantee. See app/crypto/profiles.py for the
literature-grounded rationale for why this is a real, narrow contribution
rather than a re-badging of existing work.

To keep the traditional-vs-proposed comparison fair, the "traditional"
baseline path fixes on ML-KEM-768 -- the parameter set most healthcare
PQC guidance recommends as a general-purpose default -- with no
per-operation adaptation and no HKDF context binding, so the comparison
isolates exactly what adaptivity (Step 2) and context binding (Step 5)
each add.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone

import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto.profiles import OPERATION_TYPE_TO_PROFILE

# Traditional/baseline path fixes on this parameter set -- see module
# docstring and profiles.py for why ML-KEM-768 is the fair baseline choice.
TRADITIONAL_ML_KEM_ALG = "ML-KEM-768"


# ---------------------------------------------------------------------------
# KyberKEM -- thin wrapper giving liboqs-python's ML-KEM the same
# three-function interface (KeyGen / Encaps / Decaps) the rest of this
# module already expects, parameterised by which ML-KEM strength to use.
# ---------------------------------------------------------------------------

class KyberKEM:
    """
    Real CRYSTALS-Kyber / ML-KEM, via liboqs (Open Quantum Safe).
    NIST FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism.

    alg : "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024"
    """

    def __init__(self, alg: str = "ML-KEM-768"):
        if alg not in {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}:
            raise ValueError(f"Unsupported ML-KEM parameter set: {alg!r}")
        self.alg = alg

    def KeyGen(self) -> tuple[bytes, bytes]:
        """Returns (public_key, secret_key)."""
        with oqs.KeyEncapsulation(self.alg) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return pk, sk

    def Encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_key K2)."""
        with oqs.KeyEncapsulation(self.alg) as kem:
            ciphertext, shared_secret = kem.encap_secret(pk)
        return ciphertext, shared_secret

    def Decaps(self, ciphertext: bytes, sk: bytes) -> bytes:
        """Recovers shared_key K2 from ciphertext and secret key."""
        with oqs.KeyEncapsulation(self.alg, sk) as kem:
            return kem.decap_secret(ciphertext)


# Backwards-compatible alias: earlier code/tests refer to Kyber768KEM.
# It is now just KyberKEM fixed to ML-KEM-768.
class Kyber768KEM(KyberKEM):
    def __init__(self):
        super().__init__("ML-KEM-768")


_kyber_by_alg: dict[str, KyberKEM] = {}


def _kyber_for(alg: str) -> KyberKEM:
    """Cached KyberKEM instance per parameter set (KyberKEM itself is stateless)."""
    if alg not in _kyber_by_alg:
        _kyber_by_alg[alg] = KyberKEM(alg)
    return _kyber_by_alg[alg]


# ---------------------------------------------------------------------------
# Pure derivation core -- separated so it can be unit-tested with fixed
# inputs (no ECC/Kyber randomness in the way).
# ---------------------------------------------------------------------------

def normalize(K1: bytes, K2: bytes) -> tuple[bytes, bytes]:
    """Step 3: SHA-256 normalisation. Uniform 32-byte output, no structure."""
    return hashlib.sha256(K1).digest(), hashlib.sha256(K2).digest()


def fuse(K1_norm: bytes, K2_norm: bytes) -> bytes:
    """
    Step 4: secure key fusion.

    Always combines the FULL normalised secret from both legs. This is
    the fix for the truncation flaw: Kf depends on every bit of both K1'
    and K2', so an adversary who has broken one leg still faces the full
    256-bit search space of the other.
    """
    return hashlib.sha256(K1_norm + K2_norm).digest()


def derive_kfinal(Kf: bytes, sid: str, t: str, pid: str, hkdf_info: bytes) -> bytes:
    """Step 5: context-aware HKDF derivation with profile domain separation."""
    Kc = Kf + sid.encode() + t.encode() + pid.encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=hkdf_info,
    ).derive(Kc)


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def establish_session_key(
    operation_type: str,
    context_id: str,
    db=None,
    mode: str = "proposed",
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
    dict -- see keys below; kfinal (bytes) is the ready-to-use AES-256 key
    """
    profile = OPERATION_TYPE_TO_PROFILE.get(operation_type)
    if profile is None:
        raise ValueError(
            f"Unknown operation_type '{operation_type}'. "
            f"Expected one of: {list(OPERATION_TYPE_TO_PROFILE.keys())}"
        )

    mode = (mode or "proposed").strip().lower()
    if mode not in {"proposed", "traditional"}:
        raise ValueError("mode must be 'proposed' or 'traditional'")

    if mode == "traditional":
        result = traditional_hybrid_keygen(context_id)
        result["operation_type"] = operation_type
        result["context_id"] = str(context_id)
        result["profile_name"] = profile["name"]
        if db is not None:
            _write_log(db, result)
        return result

    alpha: float = profile["alpha"]
    beta: float  = profile["beta"]
    kem_alg: str = profile["kem_alg"]
    kyber = _kyber_for(kem_alg)

    t_start = time.perf_counter()

    # -- Step 1: ECC (X25519) key exchange -----------------------------------
    doctor_private  = X25519PrivateKey.generate()
    patient_private = X25519PrivateKey.generate()
    K1 = doctor_private.exchange(patient_private.public_key())

    # -- Step 2: ML-KEM key encapsulation (profile-selected strength) -------
    pk, sk = kyber.KeyGen()
    ciphertext, K2 = kyber.Encaps(pk)

    # -- Step 3: Key normalisation (SHA-256) ---------------------------------
    K1_norm, K2_norm = normalize(K1, K2)

    # -- Step 4: Secure key fusion (full entropy, no truncation) -------------
    Kf = fuse(K1_norm, K2_norm)
    bytes_from_k1 = len(K1_norm)  # always 32 -- see profiles.py revision note
    bytes_from_k2 = len(K2_norm)  # always 32

    # -- Step 5: Context-aware key derivation (HKDF) -------------------------
    SID = str(uuid.uuid4())
    T   = datetime.now(timezone.utc).isoformat()
    PID = str(context_id)
    Kfinal = derive_kfinal(Kf, SID, T, PID, profile["hkdf_info"])

    t_end = time.perf_counter()
    execution_time_ms = round((t_end - t_start) * 1000, 3)

    result = {
        # The usable key -- never logged or returned to the client
        "kfinal":            Kfinal,
        # Profile metadata (alpha/beta are descriptive only, see profiles.py)
        "alpha":             alpha,
        "beta":              beta,
        "profile_name":      profile["name"],
        "operation_type":    operation_type,
        "context_id":        PID,
        "encryption_mode":   "proposed",
        # Which ML-KEM strength this profile picked, and its real wire cost
        "kem_alg":           kem_alg,
        "kem_public_key_bytes": len(pk),
        "kem_ciphertext_bytes": len(ciphertext),
        # Key fusion accounting -- both always 32 now (full entropy)
        "bytes_from_k1":     bytes_from_k1,
        "bytes_from_k2":     bytes_from_k2,
        "hkdf_info":         profile["hkdf_info"].decode(),
        # Preview values (first 8 hex chars -- safe to display)
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
                "label":   f"{kem_alg} Encapsulation → K2",
                "preview": K2.hex()[:16],
                "kem_alg": kem_alg,
                "public_key_bytes": len(pk),
                "ciphertext_bytes": len(ciphertext),
            },
            "step3": {
                "label":    "SHA-256 Normalisation → K1′, K2′",
                "k1_prime": K1_norm.hex()[:16],
                "k2_prime": K2_norm.hex()[:16],
            },
            "step4": {
                "label":         "Full-Entropy Fusion → Kf",
                "preview":       Kf.hex()[:16],
                "bytes_from_k1": bytes_from_k1,
                "bytes_from_k2": bytes_from_k2,
            },
            "step5": {
                "label":     "HKDF Context Derivation → Kfinal",
                "preview":   Kfinal.hex()[:16],
                "sid":       SID,
                "pid":       PID,
                "hkdf_info": profile["hkdf_info"].decode(),
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


def traditional_hybrid_keygen(context_id: str) -> dict:
    """
    Naive baseline session-key generation: full-entropy concatenation,
    no weighting story, no context binding. Uses the SAME real
    ML-KEM-768 implementation as the proposed pipeline so the comparison
    is apples-to-apples.
    """
    t_start = time.perf_counter()

    kyber = _kyber_for(TRADITIONAL_ML_KEM_ALG)

    doctor_private = X25519PrivateKey.generate()
    patient_private = X25519PrivateKey.generate()
    K1 = doctor_private.exchange(patient_private.public_key())

    pk, _sk = kyber.KeyGen()
    ciphertext, K2 = kyber.Encaps(pk)

    K1_norm, K2_norm = normalize(K1, K2)

    Kfinal = hashlib.sha256(K1 + K2).digest()
    SID = str(uuid.uuid4())
    T = datetime.now(timezone.utc).isoformat()
    PID = str(context_id)

    t_end = time.perf_counter()
    execution_time_ms = round((t_end - t_start) * 1000, 3)

    return {
        "kfinal": Kfinal,
        # 1.0/1.0, not 0.5/0.5: this baseline also concatenates the FULL
        # K1 and K2 (see profiles.py's note on why alpha/beta are 1.0 now,
        # not a pair that sums to 1). Kept only for the NOT NULL log schema.
        "alpha": 1.0,
        "beta": 1.0,
        "profile_name": "TRADITIONAL_BASELINE",
        "operation_type": "traditional",
        "context_id": PID,
        "encryption_mode": "traditional",
        "kem_alg": TRADITIONAL_ML_KEM_ALG,
        "kem_public_key_bytes": len(pk),
        "kem_ciphertext_bytes": len(ciphertext),
        "bytes_from_k1": 32,
        "bytes_from_k2": 32,
        "hkdf_info": "(none -- no context binding)",
        "k1_prime_preview": K1_norm.hex()[:8],
        "k2_prime_preview": K2_norm.hex()[:8],
        "kf_preview": Kfinal.hex()[:8],
        "kfinal_preview": Kfinal.hex()[:8],
        "sid": SID,
        "timestamp": T,
        "execution_time_ms": execution_time_ms,
        "step_details": {
            "step1": {
                "label": "ECC X25519 Exchange → K1",
                "preview": K1.hex()[:16],
            },
            "step2": {
                "label": f"{TRADITIONAL_ML_KEM_ALG} Encapsulation → K2",
                "preview": K2.hex()[:16],
                "kem_alg": TRADITIONAL_ML_KEM_ALG,
                "public_key_bytes": len(pk),
                "ciphertext_bytes": len(ciphertext),
            },
            "step3": {
                "label": "SHA-256 Normalisation → K1′, K2′",
                "k1_prime": K1_norm.hex()[:16],
                "k2_prime": K2_norm.hex()[:16],
            },
            "step4": {
                "label": "Naive Fusion → Kfinal",
                "preview": Kfinal.hex()[:16],
                "bytes_from_k1": 32,
                "bytes_from_k2": 32,
            },
            "step5": {
                "label": "No Context Binding",
                "preview": Kfinal.hex()[:16],
                "sid": SID,
                "pid": PID,
            },
            "step6": {
                "label": "AES-256-GCM Ready",
                "key_preview": Kfinal.hex()[:8],
            },
        },
    }


def _write_log(db, result: dict) -> None:
    """Inserts a CryptoOperationLog row. Non-fatal on failure."""
    from app.models import CryptoOperationLog
    try:
        log = CryptoOperationLog(
            operation_type=result["operation_type"],
            encryption_mode=result.get("encryption_mode", "proposed"),
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
# Key wrapping -- stores kfinal securely alongside the encrypted record
# ---------------------------------------------------------------------------
# Because ECC and Kyber keys are ephemeral, kfinal changes on every call to
# establish_session_key(). To decrypt a stored record later we need the
# original kfinal. We wrap (encrypt) it under a server master key derived
# from SESSION_SECRET via HKDF, then store the wrapped form in the DB.
# This is standard practice (RFC 3394 / AES key wrapping). The master key
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
    Returns a single string "nonce_hex:ciphertext_hex" for DB storage.
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
