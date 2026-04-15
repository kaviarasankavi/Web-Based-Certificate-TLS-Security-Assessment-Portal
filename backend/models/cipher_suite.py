import uuid

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from database import PGBase


def generate_uuid():
    return str(uuid.uuid4())


class CipherSuiteResult(PGBase):
    __tablename__ = "cipher_suite_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    cipher_name = Column(String(200))
    protocol = Column(String(20))
    key_exchange = Column(String(50))
    strength = Column(String(20))
    is_dangerous = Column(Boolean, default=False)
    bits = Column(Integer)

    scan = relationship("Scan", back_populates="cipher_suites")
