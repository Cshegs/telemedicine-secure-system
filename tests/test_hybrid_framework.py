import hashlib

from app.crypto import hybrid_fusion as hf
from app.crypto.profiles import SPEED_PROFILE, BALANCED_PROFILE, SECURITY_PROFILE


def test_ecc_shared_secret_matches():
    doctor_private = hf.X25519PrivateKey.generate()
    patient_private = hf.X25519PrivateKey.generate()

    k1_doctor = doctor_private.exchange(patient_private.public_key())
    k1_patient = patient_private.exchange(doctor_private.public_key())

    assert k1_doctor == k1_patient, "ECC shared secret mismatch: both parties must derive the same K1"


def test_kyber_shared_secret_matches():
    """Real ML-KEM-768 (liboqs), not a placeholder: Encaps/Decaps must agree."""
    kyber = hf.Kyber768KEM()
    pk, sk = kyber.KeyGen()

    ciphertext, k2_encaps = kyber.Encaps(pk)
    k2_decaps = kyber.Decaps(ciphertext, sk)

    assert k2_encaps == k2_decaps, "Kyber shared secret mismatch: Encaps and Decaps must derive the same K2"


def test_kyber_shared_secret_matches_for_every_parameter_set():
    """
    v3: profiles now select different ML-KEM parameter sets (512/768/1024).
    Encaps/Decaps must agree for all three, and each must report the real,
    NIST-published key/ciphertext sizes for that parameter set -- not the
    same size regardless of which one was requested.
    """
    expected_sizes = {
        # alg: (public_key_bytes, ciphertext_bytes)
        "ML-KEM-512":  (800, 768),
        "ML-KEM-768":  (1184, 1088),
        "ML-KEM-1024": (1568, 1568),
    }
    for alg, (expected_pk_len, expected_ct_len) in expected_sizes.items():
        kyber = hf.KyberKEM(alg)
        pk, sk = kyber.KeyGen()
        ciphertext, k2_encaps = kyber.Encaps(pk)
        k2_decaps = kyber.Decaps(ciphertext, sk)

        assert k2_encaps == k2_decaps, f"{alg}: Encaps/Decaps shared secret mismatch"
        assert len(k2_encaps) == 32, f"{alg}: ML-KEM shared secret must always be 32 bytes"
        assert len(pk) == expected_pk_len, f"{alg}: unexpected public key size"
        assert len(ciphertext) == expected_ct_len, f"{alg}: unexpected ciphertext size"


def test_normalization_output_length():
    doctor_private = hf.X25519PrivateKey.generate()
    patient_private = hf.X25519PrivateKey.generate()
    k1 = doctor_private.exchange(patient_private.public_key())

    kyber = hf.Kyber768KEM()
    pk, _ = kyber.KeyGen()
    _, k2 = kyber.Encaps(pk)

    k1_prime, k2_prime = hf.normalize(k1, k2)

    assert len(k1_prime) == 32, "K1' length must be exactly 32 bytes after SHA-256 normalization"
    assert len(k2_prime) == 32, "K2' length must be exactly 32 bytes after SHA-256 normalization"


def test_fusion_uses_full_entropy_speed_profile():
    """
    Regression test for the truncation flaw a reviewer identified: v1 kept
    only round(alpha*32) / round(beta*32) bytes of each normalised secret
    before fusing (e.g. SECURITY_PROFILE kept only 6 bytes / 48 bits of
    K1'). Fixed version must always report the full 32 bytes from both legs,
    regardless of which profile -- and which ML-KEM parameter set -- is
    selected.
    """
    result = hf.establish_session_key("video_call", "speed-profile-test")

    assert result["profile_name"] == "SPEED_PROFILE"
    assert result["kem_alg"] == "ML-KEM-512"
    assert result["bytes_from_k1"] == 32, "Fusion must use the full K1' (32 bytes), not a truncated slice"
    assert result["bytes_from_k2"] == 32, "Fusion must use the full K2' (32 bytes), not a truncated slice"


def test_fusion_uses_full_entropy_security_profile():
    """Same check under SECURITY_PROFILE, the profile that was weakest under the old truncation scheme."""
    result = hf.establish_session_key("patient_record", "security-profile-test")

    assert result["profile_name"] == "SECURITY_PROFILE"
    assert result["kem_alg"] == "ML-KEM-1024"
    assert result["bytes_from_k1"] == 32, "Fusion must use the full K1' (32 bytes), not a truncated slice"
    assert result["bytes_from_k2"] == 32, "Fusion must use the full K2' (32 bytes), not a truncated slice"


def test_profiles_select_distinct_ml_kem_parameter_sets():
    """
    v3: alpha/beta's real job is selecting ML-KEM strength per operation
    type. Confirms the three profiles actually differ (not just in name)
    and that a higher-security profile has a strictly larger real
    ciphertext -- i.e. security-vs-cost is a genuine, measurable trade-off,
    not a cosmetic label.
    """
    speed = hf.establish_session_key("video_call", "param-set-check")
    balanced = hf.establish_session_key("chat", "param-set-check")
    security = hf.establish_session_key("patient_record", "param-set-check")

    algs = {speed["kem_alg"], balanced["kem_alg"], security["kem_alg"]}
    assert algs == {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}, (
        "Each profile must select a distinct ML-KEM parameter set"
    )
    assert (
        speed["kem_ciphertext_bytes"]
        < balanced["kem_ciphertext_bytes"]
        < security["kem_ciphertext_bytes"]
    ), "Ciphertext size must strictly increase with profile security level"


def test_fused_key_depends_on_every_byte_of_k1_prime():
    """
    Directly disproves the reviewer's attack: under the old scheme, only
    the first 6 bytes of K1' fed SECURITY_PROFILE's fusion, so an
    adversary who broke Kyber never needed to recover the rest of K1'.
    Here we flip a single byte of K1' *after* byte 6 (well outside the old
    truncation boundary) and confirm Kf still changes -- proving Kf is
    sensitive to bytes that the old design would have discarded entirely.
    """
    k1_prime = hashlib.sha256(b"fixed-k1-for-test").digest()
    k2_prime = hashlib.sha256(b"fixed-k2-for-test").digest()

    kf_original = hf.fuse(k1_prime, k2_prime)

    tampered = bytearray(k1_prime)
    tampered[20] ^= 0x01  # flip one bit at byte index 20 (>> old 6-byte SECURITY_PROFILE cutoff)
    kf_tampered = hf.fuse(bytes(tampered), k2_prime)

    assert kf_original != kf_tampered, (
        "Kf must depend on the full 32 bytes of K1'; a byte past the old truncation "
        "boundary changed and Kf did not, which would reproduce the original flaw"
    )


def test_profiles_apply_distinct_hkdf_domain_separation():
    """
    alpha/beta no longer control byte allocation (see profiles.py); the
    real, testable property they now control is HKDF domain separation.
    Identical (Kf, SID, T, PID) under two different profiles must still
    produce different Kfinal values.
    """
    kf = hashlib.sha256(b"fixed-kf-for-domain-separation-test").digest()
    sid, t, pid = "fixed-sid", "fixed-timestamp", "fixed-patient"

    k_speed = hf.derive_kfinal(kf, sid, t, pid, SPEED_PROFILE["hkdf_info"])
    k_balanced = hf.derive_kfinal(kf, sid, t, pid, BALANCED_PROFILE["hkdf_info"])
    k_security = hf.derive_kfinal(kf, sid, t, pid, SECURITY_PROFILE["hkdf_info"])

    assert len({k_speed, k_balanced, k_security}) == 3, (
        "Each profile's HKDF info label must produce a distinct Kfinal from identical inputs"
    )


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


def test_traditional_baseline_uses_real_kyber_too():
    """
    Fairness check: the 'traditional' comparison baseline must use real
    ML-KEM (fixed at ML-KEM-768, the general-purpose default), so any
    timing comparison against the adaptive profiles is apples-to-apples
    on cryptographic correctness -- the only fair thing that should differ
    is which parameter set gets used and whether context binding applies.
    """
    result = hf.traditional_hybrid_keygen("baseline-fairness-check")
    assert result["kem_alg"] == "ML-KEM-768"
    assert result["bytes_from_k1"] == 32
    assert result["bytes_from_k2"] == 32
    assert len(result["kfinal"]) == 32
