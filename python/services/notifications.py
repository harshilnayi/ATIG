import requests
import logging
from typing import List, Dict, Optional
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class NotificationManager:
    """Send alerts to various notification channels"""

    def __init__(self):
        self.webhooks: List[Dict] = []
        self.email_config = {}
        self.slack_config = {}

    def add_webhook(self, url: str, events: List[str] = None, severity_filter: List[str] = None):
        """Add a webhook endpoint for notifications"""
        self.webhooks.append({
            'url': url,
            'events': events or ['all'],
            'severity_filter': severity_filter or ['critical', 'high', 'medium', 'low']
        })
        logger.info(f"Added webhook: {url}")

    def send_notification(self, alert: Dict):
        """Send alert to all configured channels"""
        severity = alert.get('severity', 'medium')

        for webhook in self.webhooks:
            if severity not in webhook.get('severity_filter', []):
                continue

            try:
                payload = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'alert': alert,
                    'message': self._format_message(alert)
                }

                response = requests.post(
                    webhook['url'],
                    json=payload,
                    timeout=10
                )

                if response.status_code == 200:
                    logger.info(f"Notification sent to {webhook['url']}")
                else:
                    logger.error(f"Webhook failed: {response.status_code}")

            except Exception as e:
                logger.error(f"Notification error for {webhook['url']}: {e}")

    def _format_message(self, alert: Dict) -> str:
        """Format alert message for notifications"""
        severity = alert.get('severity', 'unknown').upper()
        alert_type = alert.get('type', 'UNKNOWN')
        message = alert.get('message', alert.get('signature_msg', 'No message'))
        src_ip = alert.get('src_ip', alert.get('source_ip', 'N/A'))

        return f"[{severity}] {alert_type}: {message} (Source: {src_ip})"

    def send_slack(self, alert: Dict, webhook_url: str = None):
        """Send alert to Slack"""
        url = webhook_url or self.slack_config.get('webhook_url')
        if not url:
            logger.warning("No Slack webhook URL configured")
            return

        try:
            color = {
                'critical': '#ff0000',
                'high': '#ff6600',
                'medium': '#ffcc00',
                'low': '#36a64f'
            }.get(alert.get('severity', 'medium'), '#808080')

            payload = {
                'attachments': [{
                    'color': color,
                    'title': f"ATIG Alert - {alert.get('severity', 'Unknown').upper()}",
                    'text': alert.get('message', alert.get('signature_msg', '')),
                    'fields': [
                        {'title': 'Source IP', 'value': alert.get('src_ip', 'N/A'), 'short': True},
                        {'title': 'Dest IP', 'value': alert.get('dst_ip', 'N/A'), 'short': True},
                        {'title': 'Type', 'value': alert.get('type', 'N/A'), 'short': True},
                        {'title': 'Protocol', 'value': alert.get('protocol', 'N/A'), 'short': True}
                    ],
                    'timestamp': int(datetime.utcnow().timestamp())
                }]
            }

            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200

        except Exception as e:
            logger.error(f"Slack notification error: {e}")
            return False

    def send_email(self, to: str, alert: Dict):
        """Send alert via email (placeholder - requires SMTP setup)"""
        # This would need actual SMTP configuration
        logger.info(f"Email notification to {to}: {alert.get('message', 'Alert')}")
        return True
