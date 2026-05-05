import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

class ThreatScorer:
    """Real-time threat scoring based on alert patterns and IP reputation"""

    def __init__(self):
        self.ip_scores = defaultdict(lambda: {'score': 0, 'alerts': [], 'last_seen': None})
        self.ip_alert_counts = defaultdict(int)
        self.thresholds = {
            'low': 10,
            'medium': 30,
            'high': 60,
            'critical': 80
        }
        self.decay_rate = 0.95  # Score decay per minute
        self.max_score = 100

    def calculate_threat_score(self, alert_data: Dict) -> Dict:
        """Calculate real-time threat score for an IP based on alert patterns"""
        src_ip = alert_data.get('source_ip')
        if not src_ip:
            return {'threat_score': 0, 'risk_level': 'low', 'trend': 'stable'}

        # Initialize or update IP tracking
        ip_data = self.ip_scores[src_ip]
        current_time = datetime.utcnow()

        # Decay old scores
        if ip_data['last_seen']:
            time_diff = (current_time - ip_data['last_seen']).total_seconds() / 60
            ip_data['score'] *= (self.decay_rate ** time_diff)

        # Add alert weight based on severity
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3
        }

        severity = alert_data.get('severity', 'medium')
        weight = severity_weights.get(severity, 5)

        ip_data['score'] = min(ip_data['score'] + weight, self.max_score)
        ip_data['alerts'].append({
            'type': alert_data.get('detection_type'),
            'timestamp': current_time,
            'severity': severity
        })
        ip_data['last_seen'] = current_time

        # Keep only last 50 alerts
        if len(ip_data['alerts']) > 50:
            ip_data['alerts'] = ip_data['alerts'][-50:]

        # Determine risk level
        score = ip_data['score']
        if score >= self.thresholds['critical']:
            risk_level = 'critical'
        elif score >= self.thresholds['high']:
            risk_level = 'high'
        elif score >= self.thresholds['medium']:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        # Calculate trend
        recent_alerts = [a for a in ip_data['alerts']
                        if (current_time - a['timestamp']).total_seconds() < 300]
        trend = 'rising' if len(recent_alerts) > 3 else 'stable'

        return {
            'threat_score': round(score, 2),
            'risk_level': risk_level,
            'trend': trend,
            'alert_count': ip_data['alert_count'] if 'alert_count' in ip_data else len(ip_data['alerts'])
        }

    def get_ip_reputation(self, ip: str) -> Dict:
        """Get reputation score and history for an IP"""
        ip_data = self.ip_scores.get(ip, {'score': 0, 'alerts': [], 'last_seen': None})

        return {
            'ip': ip,
            'reputation_score': max(0, 100 - ip_data['score']),
            'total_alerts': len(ip_data['alerts']),
            'last_seen': ip_data['last_seen'].isoformat() if ip_data['last_seen'] else None,
            'recent_alerts': [
                {'type': a['type'], 'severity': a['severity']}
                for a in ip_data['alerts'][-5:]
            ]
        }

    def get_top_threats(self, limit: int = 10) -> List[Dict]:
        """Get top N most dangerous IPs"""
        sorted_ips = sorted(
            self.ip_scores.items(),
            key=lambda x: x[1]['score'],
            reverse=True
        )[:limit]

        return [
            {
                'ip': ip,
                'threat_score': data['score'],
                'alert_count': len(data['alerts']),
                'risk_level': 'critical' if data['score'] >= self.thresholds['critical'] else
                             'high' if data['score'] >= self.thresholds['high'] else
                             'medium' if data['score'] >= self.thresholds['medium'] else 'low'
            }
            for ip, data in sorted_ips
        ]

    def reset_ip_score(self, ip: str):
        """Reset threat score for an IP (e.g., after blocking or whitelisting)"""
        if ip in self.ip_scores:
            self.ip_scores[ip] = {'score': 0, 'alerts': [], 'last_seen': None}


class AlertCorrelator:
    """Correlate alerts to detect sophisticated attack patterns"""

    def __init__(self):
        self.alert_window = defaultdict(list)
        self.correlation_rules = [
            {
                'name': 'SQL Injection Chain',
                'patterns': ['SQL Injection'],
                'time_window': 300,
                'min_count': 3,
                'severity': 'high'
            },
            {
                'name': 'Multi-Port Scan',
                'patterns': ['SCAN'],
                'time_window': 60,
                'min_count': 5,
                'severity': 'medium'
            },
            {
                'name': 'Brute Force + Exploit',
                'patterns': ['Brute Force', 'EXPLOIT'],
                'time_window': 600,
                'min_count': 2,
                'severity': 'critical'
            },
            {
                'name': 'Recon + Data Exfil',
                'patterns': ['SCAN', 'DATA_EXFIL'],
                'time_window': 1800,
                'min_count': 2,
                'severity': 'critical'
            }
        ]

    def correlate_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Find correlated attack patterns in recent alerts"""
        correlations = []

        for rule in self.correlation_rules:
            matching_alerts = []
            for alert in alerts[-100:]:  # Check last 100 alerts
                for pattern in rule['patterns']:
                    if pattern.lower() in alert.get('signature_msg', '').lower() or \
                       pattern.lower() in alert.get('message', '').lower():
                        matching_alerts.append(alert)
                        break

            if len(matching_alerts) >= rule['min_count']:
                # Check time window
                recent = [a for a in matching_alerts
                         if (datetime.utcnow() - a.get('timestamp', datetime.utcnow())).total_seconds()
                         < rule['time_window']]

                if len(recent) >= rule['min_count']:
                    source_ips = list(set(a.get('source_ip') for a in recent if a.get('source_ip')))
                    correlations.append({
                        'correlation_name': rule['name'],
                        'severity': rule['severity'],
                        'matched_alerts': len(recent),
                        'source_ips': source_ips,
                        'first_seen': min(a.get('timestamp', datetime.utcnow()) for a in recent),
                        'last_seen': max(a.get('timestamp', datetime.utcnow()) for a in recent)
                    })

        return correlations
