from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import logging
import asyncio
from datetime import datetime, timedelta

from models.database import get_db, Alert, DetectionRule, init_db
from engine.signatures import SignatureEngine, DetectionResult
from engine.ml_model import AnomalyDetector, BaselineLearner
from engine.threat_scoring import ThreatScorer, AlertCorrelator
from engine.response import RateLimiter
from services.threat_intel import ThreatIntelAggregator
from services.notifications import NotificationManager

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
threat_scorer = ThreatScorer()
alert_correlator = AlertCorrelator()
recent_alerts = []  # Store last 100 alerts for correlation

active_connections: List[WebSocket] = []
rate_limiter = RateLimiter()
notification_manager = NotificationManager()

@app.on_event("startup")
async def startup():
    logger.info("ATIG API starting up...")
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database initialization skipped: {e}")
        logger.warning("Running without database persistence")
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


@app.get("/threats/top")
def get_top_threats(limit: int = 10):
    """Get top N most dangerous IPs based on threat scoring"""
    return {"top_threats": threat_scorer.get_top_threats(limit)}


@app.get("/threats/ip/{ip}")
def get_ip_threat_info(ip: str):
    """Get detailed threat information for a specific IP"""
    return threat_scorer.get_ip_reputation(ip)


@app.get("/threats/correlations")
def get_alert_correlations():
    """Get correlated attack patterns"""
    return {"correlations": alert_correlator.correlate_alerts(recent_alerts)}


@app.get("/dashboard/extended-stats")
def get_extended_stats(db: Session = Depends(get_db)):
    """Extended dashboard stats with threat scores and correlations"""
    total_alerts = db.query(Alert).count()
    high_severity = db.query(Alert).filter(Alert.severity == "high").count()
    signature_alerts = db.query(Alert).filter(Alert.detection_type == "SIGNATURE").count()
    anomaly_alerts = db.query(Alert).filter(Alert.detection_type == "ANOMALY").count()

    return {
        "total_alerts": total_alerts,
        "high_severity": high_severity,
        "signature_detections": signature_alerts,
        "anomaly_detections": anomaly_alerts,
        "threat_intel_indicators": sum(len(v) for v in threat_intel.indicators.values()),
        "top_threats": threat_scorer.get_top_threats(5),
        "active_correlations": len(alert_correlator.correlate_alerts(recent_alerts))
    }


# === RESPONSE AUTOMATION ENDPOINTS ===

@app.post("/block/ip/{ip}")
def block_ip_endpoint(ip: str, duration: int = 3600, reason: str = "manual"):
    """Manually block an IP address"""
    return rate_limiter.block_ip(ip, duration, reason)


@app.delete("/block/ip/{ip}")
def unblock_ip_endpoint(ip: str):
    """Unblock an IP address"""
    return rate_limiter.unblock_ip(ip)


@app.get("/blocked")
def get_blocked_ips():
    """Get list of currently blocked IPs"""
    rate_limiter.cleanup_expired_blocks()
    return {"blocked_ips": rate_limiter.get_blocked_ips()}


@app.get("/rate-limit/check/{ip}")
def check_rate_limit(ip: str, port: int = 80):
    """Check if an IP is rate limited"""
    return rate_limiter.check_rate_limit(ip, port)


# === NOTIFICATION ENDPOINTS ===

@app.get("/notifications/webhooks")
def list_webhooks():
    """List configured webhooks"""
    return {"webhooks": notification_manager.webhooks}


@app.post("/notifications/webhooks")
def add_webhook(url: str, events: str = None, severities: str = None):
    """Add webhook for notifications"""
    event_list = events.split(',') if events else None
    severity_list = severities.split(',') if severities else None
    notification_manager.add_webhook(url, event_list, severity_list)
    return {"status": "webhook_added", "url": url}


@app.get("/alerts/recent")
def get_recent_alerts(limit: int = 50, db: Session = Depends(get_db)):
    """Get recent alerts with correlation info"""
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()

    # Get correlations
    correlations = alert_correlator.correlate_alerts(recent_alerts)

    return {
        "alerts": [{
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity,
            "type": a.detection_type,
            "src_ip": str(a.source_ip) if a.source_ip else None,
            "dst_ip": str(a.dest_ip) if a.dest_ip else None,
            "message": a.signature_msg
        } for a in alerts],
        "correlations": correlations
    }


@app.get("/alerts/by-severity/{severity}")
def get_alerts_by_severity(severity: str, limit: int = 50, db: Session = Depends(get_db)):
    """Get alerts filtered by severity"""
    alerts = db.query(Alert).filter(
        Alert.severity == severity
    ).order_by(Alert.timestamp.desc()).limit(limit).all()

    return {
        "severity": severity,
        "count": len(alerts),
        "alerts": [{
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "src_ip": str(a.source_ip) if a.source_ip else None,
            "message": a.signature_msg
        } for a in alerts]
    }


@app.get("/alerts/by-type/{detection_type}")
def get_alerts_by_type(detection_type: str, limit: int = 50, db: Session = Depends(get_db)):
    """Get alerts filtered by detection type"""
    alerts = db.query(Alert).filter(
        Alert.detection_type == detection_type.upper()
    ).order_by(Alert.timestamp.desc()).limit(limit).all()

    return {
        "type": detection_type,
        "count": len(alerts),
        "alerts": [{
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity,
            "src_ip": str(a.source_ip) if a.source_ip else None,
            "message": a.signature_msg
        } for a in alerts]
    }


@app.get("/alerts/summary")
def get_alerts_summary(db: Session = Depends(get_db)):
    """Get summary statistics of alerts"""
    total = db.query(Alert).count()

    severity_counts = {}
    for sev in ['critical', 'high', 'medium', 'low']:
        count = db.query(Alert).filter(Alert.severity == sev).count()
        severity_counts[sev] = count

    type_counts = {}
    for dtype in ['SIGNATURE', 'ANOMALY', 'THREAT_INTEL']:
        count = db.query(Alert).filter(Alert.detection_type == dtype).count()
        type_counts[dtype] = count

    return {
        "total": total,
        "by_severity": severity_counts,
        "by_type": type_counts
    }


@app.get("/rules")
def list_detection_rules():
    """List all loaded detection rules"""
    return {
        "total_rules": len(signature_engine.rules),
        "rules": [{
            "rule_id": r.rule_id,
            "message": r.message,
            "protocol": r.protocol,
            "severity": r.severity,
            "category": r.category
        } for r in signature_engine.rules]
    }


@app.get("/rules/reload")
def reload_rules():
    """Reload detection rules from file"""
    signature_engine.rules = []
    signature_engine._load_rules_from_file()
    return {
        "status": "reloaded",
        "total_rules": len(signature_engine.rules)
    }


@app.get("/system/status")
def get_system_status():
    """Get overall system status"""
    return {
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "database": "connected",
            "threat_intel": f"{sum(len(v) for v in threat_intel.indicators.values())} indicators",
            "rules_loaded": len(signature_engine.rules),
            "blocked_ips": len(rate_limiter.blocked_ips),
            "webhooks_configured": len(notification_manager.webhooks)
        }
    }


# === ALERT SEARCH AND EXPORT ===

@app.get("/alerts/search")
def search_alerts(
    q: str = None,
    severity: str = None,
    type: str = None,
    src_ip: str = None,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Search alerts with filters"""
    query = db.query(Alert)

    if q:
        query = query.filter(
            Alert.signature_msg.ilike(f"%{q}%") |
            Alert.source_ip.ilike(f"%{q}%")
        )

    if severity:
        query = query.filter(Alert.severity == severity)

    if type:
        query = query.filter(Alert.detection_type == type.upper())

    if src_ip:
        query = query.filter(Alert.source_ip == src_ip)

    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()

    return {
        "query": q,
        "filters": {"severity": severity, "type": type, "src_ip": src_ip},
        "count": len(alerts),
        "alerts": [{
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity,
            "type": a.detection_type,
            "src_ip": str(a.source_ip) if a.source_ip else None,
            "dst_ip": str(a.dest_ip) if a.dest_ip else None,
            "message": a.signature_msg
        } for a in alerts]
    }


@app.get("/alerts/export")
def export_alerts(
    format: str = "json",
    start_date: str = None,
    end_date: str = None,
    db: Session = Depends(get_db)
):
    """Export alerts in various formats"""
    query = db.query(Alert)

    if start_date:
        try:
            start = datetime.fromisoformat(start_date)
            query = query.filter(Alert.timestamp >= start)
        except:
            pass

    if end_date:
        try:
            end = datetime.fromisoformat(end_date)
            query = query.filter(Alert.timestamp <= end)
        except:
            pass

    alerts = query.order_by(Alert.timestamp.desc()).all()

    if format == "json":
        return {
            "export": {
                "format": "json",
                "count": len(alerts),
                "generated_at": datetime.utcnow().isoformat(),
                "alerts": [{
                    "id": str(a.id),
                    "timestamp": a.timestamp.isoformat(),
                    "severity": a.severity,
                    "type": a.detection_type,
                    "src_ip": str(a.source_ip) if a.source_ip else None,
                    "dst_ip": str(a.dest_ip) if a.dest_ip else None,
                    "source_port": a.source_port,
                    "dest_port": a.dest_port,
                    "protocol": a.protocol,
                    "message": a.signature_msg
                } for a in alerts]
            }
        }

    elif format == "csv":
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "timestamp", "severity", "type", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "message"
        ])

        for a in alerts:
            writer.writerow([
                a.timestamp.isoformat(),
                a.severity,
                a.detection_type,
                str(a.source_ip) if a.source_ip else "",
                str(a.dest_ip) if a.dest_ip else "",
                a.source_port or "",
                a.dest_port or "",
                a.protocol or "",
                a.signature_msg or ""
            ])

        return {
            "format": "csv",
            "count": len(alerts),
            "data": output.getvalue()
        }

    else:
        return {"error": "Unsupported format", "supported": ["json", "csv"]}


@app.get("/dashboard/comprehensive")
def get_comprehensive_dashboard_data(db: Session = Depends(get_db)):
    """Get all dashboard data in one call"""
    total_alerts = db.query(Alert).count()
    high_severity = db.query(Alert).filter(Alert.severity == "high").count()
    signature_alerts = db.query(Alert).filter(Alert.detection_type == "SIGNATURE").count()
    anomaly_alerts = db.query(Alert).filter(Alert.detection_type == "ANOMALY").count()

    # Get recent alerts
    recent = db.query(Alert).order_by(Alert.timestamp.desc()).limit(20).all()

    # Get severity breakdown
    severity_breakdown = {}
    for sev in ['critical', 'high', 'medium', 'low']:
        count = db.query(Alert).filter(Alert.severity == sev).count()
        severity_breakdown[sev] = count

    # Get type breakdown
    type_breakdown = {}
    for dtype in ['SIGNATURE', 'ANOMALY', 'THREAT_INTEL']:
        count = db.query(Alert).filter(Alert.detection_type == dtype).count()
        type_breakdown[dtype] = count

    return {
        "stats": {
            "total_alerts": total_alerts,
            "high_severity": high_severity,
            "signature_detections": signature_alerts,
            "anomaly_detections": anomaly_alerts,
            "threat_intel_indicators": sum(len(v) for v in threat_intel.indicators.values())
        },
        "recent_alerts": [{
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity,
            "type": a.detection_type,
            "src_ip": str(a.source_ip) if a.source_ip else None,
            "dst_ip": str(a.dest_ip) if a.dest_ip else None,
            "message": a.signature_msg
        } for a in recent],
        "breakdown": {
            "by_severity": severity_breakdown,
            "by_type": type_breakdown
        },
        "top_threats": threat_scorer.get_top_threats(5),
        "correlations": alert_correlator.correlate_alerts(recent_alerts),
        "blocked_ips": len(rate_limiter.blocked_ips),
        "system_status": {
            "rules_loaded": len(signature_engine.rules),
            "webhooks_configured": len(notification_manager.webhooks)
        }
    }


@app.get("/alerts/timeline")
def get_alerts_timeline(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """Get alerts timeline for the last N hours"""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    alerts = db.query(Alert).filter(
        Alert.timestamp >= start_time
    ).order_by(Alert.timestamp.asc()).all()

    # Group by hour
    timeline = {}
    for alert in alerts:
        hour_key = alert.timestamp.strftime("%Y-%m-%d %H:00")
        if hour_key not in timeline:
            timeline[hour_key] = {
                "timestamp": hour_key,
                "total": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}
            }

        timeline[hour_key]["total"] += 1
        timeline[hour_key]["by_severity"][alert.severity] += 1

    return {
        "period": f"last {hours} hours",
        "timeline": list(timeline.values())
    }


@app.get("/alerts/acknowledge/{alert_id}")
def acknowledge_alert(alert_id: str, db: Session = Depends(get_db)):
    """Mark an alert as acknowledged"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.acknowledged = True
        db.commit()
        return {"status": "acknowledged", "alert_id": alert_id}
    return {"error": "alert not found"}


@app.get("/alerts/resolve/{alert_id}")
def resolve_alert(alert_id: str, db: Session = Depends(get_db)):
    """Mark an alert as resolved"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.resolved = True
        db.commit()
        return {"status": "resolved", "alert_id": alert_id}
    return {"error": "alert not found"}


# === ADDITIONAL ANALYTICS ENDPOINTS ===

@app.get("/analytics/alerts-by-hour")
def get_alerts_by_hour(hours: int = 24, db: Session = Depends(get_db)):
    """Get alert count by hour for the last N hours"""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    alerts = db.query(Alert).filter(
        Alert.timestamp >= start_time
    ).all()

    hourly_counts = {}
    for i in range(hours):
        hour_key = (datetime.utcnow() - timedelta(hours=i)).strftime("%Y-%m-%d %H:00")
        hourly_counts[hour_key] = 0

    for alert in alerts:
        hour_key = alert.timestamp.strftime("%Y-%m-%d %H:00")
        if hour_key in hourly_counts:
            hourly_counts[hour_key] += 1

    return {
        "period": f"last {hours} hours",
        "hourly_counts": hourly_counts
    }


@app.get("/analytics/top-ports")
def get_top_ports(limit: int = 10, db: Session = Depends(get_db)):
    """Get most frequently targeted ports"""
    alerts = db.query(Alert).all()

    port_counts = {}
    for alert in alerts:
        if alert.dest_port:
            port = alert.dest_port
            port_counts[port] = port_counts.get(port, 0) + 1

    sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    return {
        "top_ports": [
            {"port": port, "count": count}
            for port, count in sorted_ports
        ]
    }


@app.get("/analytics/top-source-ips")
def get_top_source_ips(limit: int = 10, db: Session = Depends(get_db)):
    """Get most frequent source IPs"""
    alerts = db.query(Alert).all()

    ip_counts = {}
    for alert in alerts:
        if alert.source_ip:
            ip = str(alert.source_ip)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    return {
        "top_source_ips": [
            {"ip": ip, "count": count}
            for ip, count in sorted_ips
        ]
    }


@app.get("/analytics/severity-trends")
def get_severity_trends(days: int = 7, db: Session = Depends(get_db)):
    """Get severity trends over the last N days"""
    start_time = datetime.utcnow() - timedelta(days=days)

    alerts = db.query(Alert).filter(
        Alert.timestamp >= start_time
    ).all()

    daily_trends = {}
    for i in range(days):
        day_key = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        daily_trends[day_key] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }

    for alert in alerts:
        day_key = alert.timestamp.strftime("%Y-%m-%d")
        if day_key in daily_trends:
            daily_trends[day_key][alert.severity] += 1

    return {
        "period": f"last {days} days",
        "daily_trends": daily_trends
    }


@app.get("/analytics/attack-patterns")
def get_attack_patterns(db: Session = Depends(get_db)):
    """Get common attack patterns"""
    alerts = db.query(Alert).all()

    patterns = {
        "sql_injection": 0,
        "xss": 0,
        "brute_force": 0,
        "scan": 0,
        "exploit": 0,
        "data_exfil": 0
    }

    for alert in alerts:
        msg = alert.signature_msg.lower() if alert.signature_msg else ""
        if "sql" in msg or "injection" in msg:
            patterns["sql_injection"] += 1
        elif "xss" in msg or "script" in msg:
            patterns["xss"] += 1
        elif "brute" in msg or "force" in msg:
            patterns["brute_force"] += 1
        elif "scan" in msg:
            patterns["scan"] += 1
        elif "exploit" in msg:
            patterns["exploit"] += 1
        elif "exfil" in msg or "transfer" in msg:
            patterns["data_exfil"] += 1

    return {
        "attack_patterns": [
            {"pattern": pattern, "count": count}
            for pattern, count in patterns.items()
        ]
    }


@app.get("/api-docs")
def get_api_docs():
    """Get API documentation"""
    return {
        "title": "ATIG Detection API",
        "version": "0.2.0",
        "description": "Automated Threat Intelligence Aggregator API",
        "endpoints": {
            "health": "/health",
            "analyze_packet": "/packet/analyze (POST)",
            "alerts": "/alerts",
            "stats": "/stats",
            "dashboard": "/dashboard/comprehensive",
            "threats": "/threats/top",
            "blocking": "/block/ip/{ip} (POST)",
            "rules": "/rules",
            "documentation": "See API_DOCUMENTATION.md"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
