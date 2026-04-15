import uuid

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship

from database import PGBase


def generate_uuid():
    return str(uuid.uuid4())


class ChainResult(PGBase):
    __tablename__ = "chain_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    chain_depth = Column(Integer)
    chain_valid = Column(Boolean, default=True)
    chain_data = Column(JSON, default=[])
    has_broken_chain = Column(Boolean, default=False)
    has_expired_intermediate = Column(Boolean, default=False)

    scan = relationship("Scan", back_populates="chain")
