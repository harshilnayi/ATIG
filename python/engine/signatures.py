import re
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class SignatureRule:
    rule_id: str
    message: str
    protocol: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[str]
    dst_port: Optional[str]
    content: Optional[str]
    regex: Optional[re.Pattern]
    severity: str
    category: str

@dataclass
class DetectionResult:
    rule: SignatureRule
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes

class SignatureEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules: List[SignatureRule] = []
        self.rules_dir = rules_dir
        self._load_rules_from_file()

    def _load_rules_from_file(self):
        import os
        rules_file = os.path.join(self.rules_dir, "emerging_threats.rules")
        if not os.path.exists(rules_file):
            logger.warning(f"rules file not found at {rules_file}, using defaults")
            self._compile_default_patterns()
            return

        try:
            with open(rules_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        rule = self._parse_rule(line)
                        if rule:
                            self.rules.append(rule)
                            logger.info(f"loaded rule from file: {rule.rule_id} - {rule.message}")
            logger.info(f"loaded {len(self.rules)} rules from {rules_file}")
        except Exception as e:
            logger.error(f"failed to load rules file: {e}")
            self._compile_default_patterns()

    def _compile_default_patterns(self):
        self.rules = [
            SignatureRule("1000001", "SQL Injection UNION SELECT", "tcp", None, None, None, "80", "UNION", re.compile(r"UNION", re.I), "high", "web"),
            SignatureRule("1000002", "SSH Brute Force", "tcp", None, None, None, "22", "SSH", re.compile(r"SSH", re.I), "medium", "scan"),
        ]

    def _parse_rule(self, rule_text: str) -> Optional[SignatureRule]:
        try:
            msg_match = re.search(r'msg:"([^"]+)"', rule_text)
            message = msg_match.group(1) if msg_match else "Unknown"

            sid_match = re.search(r'sid:(\d+)', rule_text)
            rule_id = sid_match.group(1) if sid_match else "0"

            proto_match = re.search(r'^(alert\s+\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)', rule_text)
            protocol = proto_match.group(2) if proto_match else "tcp"

            content_match = re.search(r'content:"([^"]+)"', rule_text)
            content = content_match.group(1) if content_match else None

            severity = "high" if "MALWARE" in message or "EXPLOIT" in message else "medium"

            return SignatureRule(
                rule_id=rule_id,
                message=message,
                protocol=protocol,
                src_ip=None,
                dst_ip=None,
                src_port=None,
                dst_port=None,
                content=content,
                regex=re.compile(re.escape(content), re.IGNORECASE) if content else None,
                severity=severity,
                category="generic"
            )
        except Exception as e:
            logger.warning(f"failed to parse rule: {e}")
            return None

    def check(self, protocol: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> List[DetectionResult]:
        results = []

        if protocol.lower() != "tcp":
            return results

        for rule in self.rules:
            if rule.protocol != protocol.lower() and rule.protocol != "any":
                continue

            if rule.regex and payload:
                if rule.regex.search(payload.decode('utf-8', errors='ignore')):
                    results.append(DetectionResult(
                        rule=rule,
                        timestamp=datetime.utcnow(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        payload=payload
                    ))

            elif rule.content and payload:
                if rule.content.lower() in payload.decode('utf-8', errors='ignore').lower():
                    results.append(DetectionResult(
                        rule=rule,
                        timestamp=datetime.utcnow(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        payload=payload
                    ))

        return results
