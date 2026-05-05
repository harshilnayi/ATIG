from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
import uuid

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///atig.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    severity = Column(String(20), nullable=False)
    detection_type = Column(String(50), nullable=False)
    source_ip = Column(String(45))
    dest_ip = Column(String(45))
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(10))
    signature_id = Column(String(50))
    signature_msg = Column(Text)
    anomaly_score = Column(Float)
    raw_payload = Column(JSON)
    acknowledged = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class NetworkFlow(Base):
    __tablename__ = "network_flows"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(10))
    bytes_sent = Column(Integer)
    bytes_received = Column(Integer)
    packets_sent = Column(Integer)
    packets_received = Column(Integer)
    flags = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    indicator_type = Column(String(20), nullable=False)
    indicator_value = Column(Text, unique=True, nullable=False)
    source = Column(String(50), nullable=False)
    confidence = Column(Integer)
    tags = Column(Text)
    first_seen = Column(DateTime)
    last_updated = Column(DateTime)
    expired = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(50), unique=True, nullable=False)
    message = Column(Text)
    protocol = Column(String(10))
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(String)
    dst_port = Column(String)
    content_match = Column(Text)
    regex_pattern = Column(Text)
    severity = Column(String(20))
    enabled = Column(Boolean, default=True)
    category = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database tables initialized successfully")
