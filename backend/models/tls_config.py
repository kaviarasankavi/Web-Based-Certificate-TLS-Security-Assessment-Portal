import uuid

from sqlalchemy import Column, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from database import PGBase


def generate_uuid():
    return str(uuid.uuid4())


class TLSConfigResult(PGBase):
    __tablename__ = "tls_config_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tls_1_0 = Column(Boolean, default=False)
    tls_1_1 = Column(Boolean, default=False)
    tls_1_2 = Column(Boolean, default=False)
    tls_1_3 = Column(Boolean, default=False)
    insecure_reneg = Column(Boolean, default=False)
    preferred_proto = Column(String(20))

    scan = relationship("Scan", back_populates="tls_config")
