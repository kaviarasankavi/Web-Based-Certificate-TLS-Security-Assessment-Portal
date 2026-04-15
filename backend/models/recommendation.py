import uuid

from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.orm import relationship

from database import PGBase


def generate_uuid():
    return str(uuid.uuid4())


class Recommendation(PGBase):
    __tablename__ = "recommendations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    severity = Column(String(20))
    title = Column(String(300))
    description = Column(Text)
    fix_suggestion = Column(Text)

    scan = relationship("Scan", back_populates="recommendations")
