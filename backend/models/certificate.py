import uuid

from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship

from database import PGBase


def generate_uuid():
    return str(uuid.uuid4())


class CertificateResult(PGBase):
    __tablename__ = "certificate_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    subject_cn = Column(String(500))
    issuer_cn = Column(String(500))
    issuer_org = Column(String(500))
    valid_from = Column(DateTime)
    valid_to = Column(DateTime)
    days_until_expiry = Column(Integer)
    is_expired = Column(Boolean, default=False)
    is_self_signed = Column(Boolean, default=False)
    serial_number = Column(Text)
    signature_algo = Column(String(100))
    public_key_type = Column(String(50))
    public_key_size = Column(Integer)
    san_list = Column(JSON, default=[])
    raw_pem = Column(Text)

    scan = relationship("Scan", back_populates="certificate")
