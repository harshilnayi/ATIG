import asyncio
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

class FeedPoller:
    def __init__(self, threat_intel):
        self.threat_intel = threat_intel
        self.running = False
        self.poll_interval = 7200

    async def start(self):
        self.running = True
        logger.info("threat intel poller started")

        while self.running:
            try:
                await self._poll_feeds()
            except Exception as e:
                logger.error(f"poller error: {e}")

            await asyncio.sleep(self.poll_interval)

    async def _poll_feeds(self):
        logger.info(f"[{datetime.utcnow().isoformat()}] polling threat feeds...")

        if self.threat_intel.otx:
            try:
                indicators = await self.threat_intel.otx.get_indicators("IPv4")
                logger.info(f"OTX: fetched {len(indicators)} IPv4 indicators")
            except Exception as e:
                logger.error(f"OTX poll failed: {e}")

        try:
            urls = await self.threat_intel.abusech.get_malware_urls()
            logger.info(f"Abuse.ch: fetched {len(urls)} malware URLs")
        except Exception as e:
            logger.error(f"Abuse.ch poll failed: {e}")

        logger.info("threat feed poll complete")

def run_poller(threat_intel):
    poller = FeedPoller(threat_intel)
    asyncio.create_task(poller.start())
