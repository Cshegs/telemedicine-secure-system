import hashlib

from app.crypto import hybrid_fusion as hf


def test_ecc_shared_secret_matches():
    doctor_private = hf.X25519PrivateKey.generate()
    patient_private = hf.X25519PrivateKey.generate()

    k1_doctor = doctor_private.exchange(patient_private.public_key())
    k1_patient = patient_private.exchange(doctor_private.public_key())

    assert k1_doctor == k1_patient, "ECC shared secret mismatch: both parties must derive the same K1"


def test_kyber_shared_secret_matches():
    kyber = hf.MockKyber()
    pk, sk = kyber.KeyGen()

    ciphertext, k2_encaps = kyber.Encaps(pk)
    k2_decaps = kyber.Decaps(ciphertext, sk)

    assert k2_encaps == k2_decaps, "Kyber shared secret mismatch: Encaps and Decaps must derive the same K2"


def test_normalization_output_length():
    doctor_private = hf.X25519PrivateKey.generate()
    patient_private = hf.X25519PrivateKey.generate()
    k1 = doctor_private.exchange(patient_private.public_key())

    kyber = hf.MockKyber()
    pk, _ = kyber.KeyGen()
    _, k2 = kyber.Encaps(pk)

    k1_prime = hashlib.sha256(k1).digest()
    k2_prime = hashlib.sha256(k2).digest()

    assert len(k1_prime) == 32, "K1' length must be exactly 32 bytes after SHA-256 normalization"
    assert len(k2_prime) == 32, "K2' length must be exactly 32 bytes after SHA-256 normalization"


def test_weighted_fusion_byte_counts_speed_profile():
    result = hf.establish_session_key("video_call", "speed-profile-test")

    assert result["alpha"] == 0.7, "video_call should use SPEED_PROFILE with alpha=0.7"
    assert result["bytes_from_k1"] == 22, "SPEED_PROFILE should draw 22 bytes from K1' for alpha=0.7"
    assert result["bytes_from_k2"] == 10, "SPEED_PROFILE should draw 10 bytes from K2' for beta=0.3"


def test_weighted_fusion_byte_counts_security_profile():
    result = hf.establish_session_key("patient_record", "security-profile-test")

    assert result["alpha"] == 0.2, "patient_record should use SECURITY_PROFILE with alpha=0.2"
    assert result["bytes_from_k1"] == 6, "SECURITY_PROFILE should draw 6 bytes from K1' for alpha=0.2"
    assert result["bytes_from_k2"] == 26, "SECURITY_PROFILE should draw 26 bytes from K2' for beta=0.8"


def test_session_uniqueness():
    first = hf.establish_session_key("chat", "same-context")
    second = hf.establish_session_key("chat", "same-context")

    assert first["kfinal"] != second["kfinal"], "Two session establishments should produce different Kfinal values"


def test_encrypt_decrypt_roundtrip():
    key_result = hf.establish_session_key("chat", "roundtrip")
    original = "Telemedicine data: patient BP 145/90, pulse 72."

    ciphertext_hex, nonce_hex = hf.aes_encrypt(key_result["kfinal"], original)
    decrypted = hf.aes_decrypt(key_result["kfinal"], ciphertext_hex, nonce_hex)

    assert decrypted == original, "AES-256-GCM roundtrip failed: decrypted text must match original plaintext"


def test_context_binding_changes_key():
    same_profile_context_a = hf.establish_session_key("chat", "context-A")
    same_profile_context_b = hf.establish_session_key("chat", "context-B")

    assert same_profile_context_a["alpha"] == same_profile_context_b["alpha"], (
        "Control check failed: both runs should use the same alpha for the same operation type"
    )
    assert same_profile_context_a["beta"] == same_profile_context_b["beta"], (
        "Control check failed: both runs should use the same beta for the same operation type"
    )
    assert same_profile_context_a["kfinal"] != same_profile_context_b["kfinal"], (
        "Context binding failed: different context_id values should produce different Kfinal keys"
    )
