import uuid

from sqlalchemy import Column, String, Boolean, Text, ForeignKey
from sqlalchemy.orm import relationship

from database import PGBase


def generate_uuid():
    return str(uuid.uuid4())


class RevocationResult(PGBase):
    __tablename__ = "revocation_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    ocsp_status = Column(String(20))
    ocsp_url = Column(Text)
    crl_present = Column(Boolean, default=False)
    crl_url = Column(Text)
    stapling_support = Column(Boolean, default=False)

    scan = relationship("Scan", back_populates="revocation")
