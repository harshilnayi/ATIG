from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import logging
import asyncio
from datetime import datetime

from models.database import get_db, Alert, DetectionRule
from engine.signatures import SignatureEngine, DetectionResult
from engine.ml_model import AnomalyDetector, BaselineLearner
from services.threat_intel import ThreatIntelAggregator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="ATIG Detection API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

signature_engine = SignatureEngine()
anomaly_detector = AnomalyDetector()
baseline_learner = BaselineLearner()
threat_intel = ThreatIntelAggregator()

active_connections: List[WebSocket] = []

@app.on_event("startup")
async def startup():
    logger.info("ATIG API starting up...")
    asyncio.create_task(background_threat_refresh())

async def background_threat_refresh():
    while True:
        try:
            await threat_intel.refresh_all()
        except Exception as e:
            logger.error(f"threat refresh error: {e}")
        await asyncio.sleep(7200)

@app.get("/")
def read_root():
    return {"status": "ATIG Detection API running", "version": "0.1.0"}

@app.get("/health")
def health_check():
    return {"health": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    logger.info(f"websocket connected: {websocket.client}")

    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)
        logger.info("websocket disconnected")

async def broadcast_alert(alert_data: dict):
    disconnected = []
    for conn in active_connections:
        try:
            await conn.send_json(alert_data)
        except:
            disconnected.append(conn)

    for conn in disconnected:
        if conn in active_connections:
            active_connections.remove(conn)

@app.post("/packet/analyze")
async def analyze_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    payload: str = "",
    db: Session = Depends(get_db)
):
    results = []

    payload_bytes = payload.encode() if payload else b""

    sig_results = signature_engine.check(protocol, src_ip, dst_ip, src_port, dst_port, payload_bytes)
    for result in sig_results:
        alert = Alert(
            severity=result.rule.severity,
            detection_type="SIGNATURE",
            source_ip=src_ip,
            dest_ip=dst_ip,
            source_port=src_port,
            dest_port=dst_port,
            protocol=protocol,
            signature_id=result.rule.rule_id,
            signature_msg=result.rule.message,
            raw_payload={"payload": payload[:1000] if payload else ""}
        )
        db.add(alert)
        results.append({
            "type": "SIGNATURE",
            "rule_id": result.rule.rule_id,
            "message": result.rule.message,
            "severity": result.rule.severity
        })

        await broadcast_alert({
            "timestamp": datetime.utcnow().isoformat(),
            "type": "SIGNATURE",
            "severity": result.rule.severity,
            "message": result.rule.message,
            "src_ip": src_ip,
            "dst_ip": dst_ip
        })

    packet_data = {
        'packet_size': len(payload_bytes),
        'packet_sizes': [len(payload_bytes)],
        'flow_duration': 1,
        'packet_count': 1,
        'bytes_per_second': len(payload_bytes),
        'tcp_flags': 1,
        'dns_queries': 1 if dst_port == 53 else 0,
        'connections': 1
    }

    baseline_learner.add_sample(packet_data)

    if len(baseline_learner.packet_sizes) >= 100:
        is_anomaly, score = anomaly_detector.is_anomaly(packet_data)
        if is_anomaly and len(baseline_learner.packet_sizes) >= 500:
            alert = Alert(
                severity="medium",
                detection_type="ANOMALY",
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=src_port,
                dest_port=dst_port,
                protocol=protocol,
                anomaly_score=score,
                raw_payload={"anomaly": True, "score": score}
            )
            db.add(alert)
            results.append({
                "type": "ANOMALY",
                "score": score,
                "message": "statistical anomaly detected"
            })

            await broadcast_alert({
                "timestamp": datetime.utcnow().isoformat(),
                "type": "ANOMALY",
                "severity": "medium",
                "score": score,
                "src_ip": src_ip,
                "dst_ip": dst_ip
            })

    threat_check = threat_intel.check_ip(src_ip)
    if threat_check:
        alert = Alert(
            severity="high",
            detection_type="THREAT_INTEL",
            source_ip=src_ip,
            dest_ip=dst_ip,
            source_port=src_port,
            dest_port=dst_port,
            protocol=protocol,
            signature_msg=f"known malicious IP: {threat_check['source']}",
            raw_payload=threat_check
        )
        db.add(alert)
        results.append({
            "type": "THREAT_INTEL",
            "source": threat_check['source'],
            "message": f"source IP in threat feed"
        })

        await broadcast_alert({
            "timestamp": datetime.utcnow().isoformat(),
            "type": "THREAT_INTEL",
            "severity": "high",
            "source": threat_check['source'],
            "src_ip": src_ip
        })

    db.commit()
    return {"analysis": results, "packets_analyzed": 1}

@app.get("/alerts")
def get_alerts(limit: int = 100, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
    return [{
        "id": str(a.id),
        "timestamp": a.timestamp.isoformat(),
        "severity": a.severity,
        "type": a.detection_type,
        "src_ip": str(a.source_ip) if a.source_ip else None,
        "dst_ip": str(a.dest_ip) if a.dest_ip else None,
        "message": a.signature_msg
    } for a in alerts]

@app.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total_alerts = db.query(Alert).count()
    high_severity = db.query(Alert).filter(Alert.severity == "high").count()
    signature_alerts = db.query(Alert).filter(Alert.detection_type == "SIGNATURE").count()
    anomaly_alerts = db.query(Alert).filter(Alert.detection_type == "ANOMALY").count()

    return {
        "total_alerts": total_alerts,
        "high_severity": high_severity,
        "signature_detections": signature_alerts,
        "anomaly_detections": anomaly_alerts,
        "threat_intel_indicators": sum(len(v) for v in threat_intel.indicators.values())
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
