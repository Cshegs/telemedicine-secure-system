"""
Weighting profiles for the hybrid ECC–Kyber key fusion pipeline.

alpha = weight given to ECC-derived key material (K1')  → speed
beta  = weight given to Kyber-derived key material (K2') → quantum resistance

alpha + beta should equal 1.0.  The bytes drawn from each component are
proportional to these weights (floor(alpha*32) and floor(beta*32) bytes
from the respective 32-byte SHA-256 normalised keys).
"""

SPEED_PROFILE = {
    "name": "SPEED_PROFILE",
    "alpha": 0.7,
    "beta": 0.3,
    "operation_type": "video_call",
    "label": "Speed-Optimised (Video Call)",
    "description": (
        "Prioritises ECC (X25519) — fast classical key exchange dominant. "
        "Suitable for live video sessions where sub-second key setup matters."
    ),
}

BALANCED_PROFILE = {
    "name": "BALANCED_PROFILE",
    "alpha": 0.4,
    "beta": 0.6,
    "operation_type": "chat",
    "label": "Balanced (Secure Chat)",
    "description": (
        "The paper's recommended optimal operating point — moderate ECC speed "
        "with majority Kyber quantum-resistance for day-to-day messaging."
    ),
}

SECURITY_PROFILE = {
    "name": "SECURITY_PROFILE",
    "alpha": 0.2,
    "beta": 0.8,
    "operation_type": "patient_record",
    "label": "Security-Maximised (Patient Records)",
    "description": (
        "Kyber-dominant fusion for records that persist for years and must "
        "resist future quantum adversaries. Slightly higher key-setup latency "
        "is acceptable for at-rest data."
    ),
}

OPERATION_TYPE_TO_PROFILE: dict[str, dict] = {
    "video_call":     SPEED_PROFILE,
    "chat":           BALANCED_PROFILE,
    "patient_record": SECURITY_PROFILE,
}
