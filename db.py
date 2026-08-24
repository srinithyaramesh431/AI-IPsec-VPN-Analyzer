"""
db.py
-----
Minimal SQLite persistence layer via SQLAlchemy. Every completed
analysis (capture -> identify -> infer -> assess -> score -> recommend)
is stored as one row so the dashboard can list history and re-render
past results without re-parsing the pcap.
"""
import datetime
import json

from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import DB_PATH

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, index=True)
    pcap_filename = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    ike_version = Column(String, nullable=True)
    security_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    ai_confidence = Column(Float, nullable=True)
    result_json = Column(Text, nullable=False)  # full pipeline output, JSON-encoded

    def to_summary(self):
        return {
            "id": self.id,
            "pcap_filename": self.pcap_filename,
            "created_at": self.created_at.isoformat(),
            "ike_version": self.ike_version,
            "security_score": self.security_score,
            "risk_level": self.risk_level,
            "ai_confidence": self.ai_confidence,
        }

    def to_full(self):
        return json.loads(self.result_json)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_analysis(db, pcap_filename, ike_version, security_score, risk_level,
                   ai_confidence, full_result: dict) -> AnalysisRecord:
    record = AnalysisRecord(
        pcap_filename=pcap_filename,
        ike_version=ike_version,
        security_score=security_score,
        risk_level=risk_level,
        ai_confidence=ai_confidence,
        result_json=json.dumps(full_result),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
