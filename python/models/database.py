from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.dialects.postgresql import INET, UUID, CIDR, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://atig:atig_dev_pass_2026@localhost:5432/atig_db")

engine = create_engine(DATABASE_URL, pool_size=10, max_overflow=20)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=lambda: None)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    severity = Column(String(20), nullable=False)
    detection_type = Column(String(50), nullable=False)
    source_ip = Column(INET)
    dest_ip = Column(INET)
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(10))
    signature_id = Column(String(50))
    signature_msg = Column(Text)
    anomaly_score = Column(Float)
    raw_payload = Column(JSON)
    acknowledged = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id = Column(UUID(as_uuid=True), primary_key=True, default=lambda: None)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True))
    src_ip = Column(INET, nullable=False)
    dst_ip = Column(INET, nullable=False)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(10))
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    packets_sent = Column(Integer)
    packets_received = Column(Integer)
    flags = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=lambda: None)
    indicator_type = Column(String(20), nullable=False)
    indicator_value = Column(Text, unique=True, nullable=False)
    source = Column(String(50), nullable=False)
    confidence = Column(Integer)
    tags = Column(ARRAY(String))
    first_seen = Column(DateTime(timezone=True))
    last_updated = Column(DateTime(timezone=True))
    expired = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=lambda: None)
    rule_id = Column(String(50), unique=True, nullable=False)
    message = Column(Text)
    protocol = Column(String(10))
    src_ip = Column(CIDR)
    dst_ip = Column(CIDR)
    src_port = Column(String)
    dst_port = Column(String)
    content_match = Column(Text)
    regex_pattern = Column(Text)
    severity = Column(String(20))
    enabled = Column(Boolean, default=True)
    category = Column(String(50))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
