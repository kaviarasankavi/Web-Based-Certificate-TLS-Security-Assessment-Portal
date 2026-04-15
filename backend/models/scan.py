import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, DateTime, Text, BigInteger, ForeignKey
from sqlalchemy.orm import relationship

from database import PGBase


def generate_uuid():
    return str(uuid.uuid4())


class Scan(PGBase):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    # FK to users table — each scan belongs to a user
    user_id = Column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_url = Column(String(500), nullable=False, index=True)
    port = Column(Integer, default=443)
    grade = Column(String(2), nullable=True)
    score = Column(Integer, nullable=True)
    status = Column(String(20), default="pending")  # pending/scanning/completed/failed
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    certificate = relationship("CertificateResult", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    tls_config = relationship("TLSConfigResult", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    cipher_suites = relationship("CipherSuiteResult", back_populates="scan", cascade="all, delete-orphan")
    revocation = relationship("RevocationResult", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    chain = relationship("ChainResult", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    recommendations = relationship("Recommendation", back_populates="scan", cascade="all, delete-orphan")
