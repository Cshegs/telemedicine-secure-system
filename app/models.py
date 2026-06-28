from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(10), nullable=False)  # "doctor" | "patient"
    assigned_doctor_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class PatientRecord(Base):
    __tablename__ = "patient_records"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    doctor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    record_type = Column(String(50), nullable=False)
    # AES-256-GCM encrypted record content (hex-encoded)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(50), nullable=False)
    # kfinal wrapped under the server master key so it can be recovered for
    # decryption without storing it in plaintext.  Format: "nonce_hex:ct_hex"
    # See hybrid_fusion.wrap_key / unwrap_key for the wrapping scheme.
    wrapped_key = Column(Text, nullable=False)
    crypto_log_id = Column(Integer, ForeignKey("crypto_operation_logs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    patient = relationship("User", foreign_keys=[patient_id])
    doctor = relationship("User", foreign_keys=[doctor_id])
    crypto_log = relationship("CryptoOperationLog")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(50), nullable=False)
    # kfinal wrapped so history can be decrypted on reload — same scheme as PatientRecord
    wrapped_key = Column(Text, nullable=False)
    crypto_log_id = Column(Integer, ForeignKey("crypto_operation_logs.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])
    crypto_log = relationship("CryptoOperationLog")


class CallSession(Base):
    __tablename__ = "call_sessions"

    id = Column(Integer, primary_key=True, index=True)
    doctor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    patient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    crypto_log_id = Column(Integer, ForeignKey("crypto_operation_logs.id"), nullable=True)

    doctor = relationship("User", foreign_keys=[doctor_id])
    patient = relationship("User", foreign_keys=[patient_id])
    crypto_log = relationship("CryptoOperationLog")


class CryptoOperationLog(Base):
    """
    Written by establish_session_key() on every crypto operation so the
    Crypto Lab dashboard can query the full history of key-fusion events.
    """
    __tablename__ = "crypto_operation_logs"

    id = Column(Integer, primary_key=True, index=True)
    operation_type = Column(String(50), nullable=False)   # video_call | chat | patient_record
    alpha = Column(Float, nullable=False)
    beta = Column(Float, nullable=False)
    bytes_from_k1 = Column(Integer, nullable=False)
    bytes_from_k2 = Column(Integer, nullable=False)
    k1_prime_preview = Column(String(20), nullable=False)  # first 8 hex chars of K1'
    k2_prime_preview = Column(String(20), nullable=False)
    kf_preview = Column(String(20), nullable=False)
    sid = Column(String(100), nullable=False)
    execution_time_ms = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
