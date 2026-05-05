import logging
from typing import Dict, List, Set
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiting and automatic blocking based on alert patterns"""

    def __init__(self):
        self.ip_request_counts = defaultdict(list)
        self.blocked_ips: Set[str] = set()
        self.blocklist = {}  # IP -> block expiration time
        self.rates = {
            'sensitive_ports': {'ports': [22, 23, 3389, 3306, 5432], 'max_requests': 10, 'window': 60},
            'web_ports': {'ports': [80, 443, 8080], 'max_requests': 100, 'window': 60},
            'all': {'ports': None, 'max_requests': 500, 'window': 60}
        }
        self.auto_block_thresholds = {
            'brute_force': {'port': 22, 'count': 5, 'window': 60, 'duration': 3600},
            'sql_injection': {'pattern': 'SQL Injection', 'count': 3, 'window': 300, 'duration': 7200},
            'scan': {'pattern': 'SCAN', 'count': 10, 'window': 60, 'duration': 1800}
        }

    def check_rate_limit(self, src_ip: str, dst_port: int) -> Dict:
        """Check if an IP is rate limited"""
        current_time = datetime.utcnow()

        # Check if IP is blocked
        if src_ip in self.blocked_ips:
            if src_ip in self.blocklist:
                if current_time < self.blocklist[src_ip]:
                    return {'allowed': False, 'reason': 'blocked', 'blocked_until': self.blocklist[src_ip]}
                else:
                    # Block expired
                    self.blocked_ips.remove(src_ip)
                    del self.blocklist[src_ip]

        # Count requests in time window
        self.ip_request_counts[src_ip] = [
            t for t in self.ip_request_counts[src_ip]
            if (current_time - t).total_seconds() < 60
        ]

        # Determine rate limit rule
        rule = self.rates['all']
        for port_name, port_rule in self.rates.items():
            if port_rule['ports'] and dst_port in port_rule['ports']:
                rule = port_rule
                break

        # Check if over limit
        request_count = len(self.ip_request_counts[src_ip])
        if request_count >= rule['max_requests']:
            return {
                'allowed': False,
                'reason': 'rate_limited',
                'current_count': request_count,
                'max_allowed': rule['max_requests'],
                'window_seconds': rule['window']
            }

        # Record this request
        self.ip_request_counts[src_ip].append(current_time)

        return {'allowed': True, 'current_count': request_count + 1}

    def should_auto_block(self, src_ip: str, alert_message: str, severity: str) -> bool:
        """Check if an IP should be automatically blocked based on alert pattern"""
        current_time = datetime.utcnow()

        for rule_name, rule in self.auto_block_thresholds.items():
            # Check if alert matches rule pattern
            if 'pattern' in rule:
                if rule['pattern'].lower() not in alert_message.lower():
                    continue

            # For port-specific rules
            if 'port' in rule:
                # This would need port info from alert - simplified here
                pass

            # Count matching alerts in time window
            # This is simplified - in production would store per-IP alert history
            logger.warning(f"Auto-block logic for {rule_name} - IP: {src_ip}")

        return False

    def block_ip(self, ip: str, duration: int = 3600, reason: str = "manual"):
        """Block an IP for a specified duration"""
        expiration = datetime.utcnow() + timedelta(seconds=duration)
        self.blocked_ips.add(ip)
        self.blocklist[ip] = expiration

        logger.info(f"IP {ip} blocked for {duration}s - Reason: {reason}")

        return {
            'ip': ip,
            'blocked': True,
            'block_duration_seconds': duration,
            'expires_at': expiration.isoformat(),
            'reason': reason
        }

    def unblock_ip(self, ip: str) -> Dict:
        """Unblock an IP"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            if ip in self.blocklist:
                del self.blocklist[ip]
            logger.info(f"IP {ip} unblocked")
            return {'ip': ip, 'unblocked': True}

        return {'ip': ip, 'unblocked': False, 'reason': 'not_blocked'}

    def get_blocked_ips(self) -> List[Dict]:
        """Get list of currently blocked IPs"""
        current_time = datetime.utcnow()
        blocked = []

        for ip, expiration in self.blocklist.items():
            remaining = (expiration - current_time).total_seconds()
            if remaining > 0:
                blocked.append({
                    'ip': ip,
                    'blocked_until': expiration.isoformat(),
                    'remaining_seconds': int(remaining)
                })

        return blocked

    def cleanup_expired_blocks(self):
        """Remove expired blocks"""
        current_time = datetime.utcnow()
        expired = [ip for ip, exp in self.blocklist.items() if exp <= current_time]

        for ip in expired:
            self.blocked_ips.discard(ip)
            del self.blocklist[ip]

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired blocks")
