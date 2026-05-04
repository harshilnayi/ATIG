import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

class OTXIntelligence:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": api_key}
        self.cache: Dict = {}
        self.cache_expiry = {}

    async def get_indicators(self, indicator_type: str = "IPv4") -> List[Dict]:
        if self._is_cached(indicator_type):
            return self.cache[indicator_type]

        url = f"{self.base_url}/indicators/{indicator_type}/subscribed"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        indicators = data.get('indications', [])
                        self._cache(indicator_type, indicators)
                        return indicators
        except Exception as e:
            logger.error(f"OTX API error: {e}")

        return []

    async def get_pulse_indicators(self, pulse_id: str) -> List[Dict]:
        url = f"{self.base_url}/pulses/{pulse_id}/indicators"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self.headers, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('indicators', [])
        except Exception as e:
            logger.error(f"OTX pulse error: {e}")

        return []

    def _is_cached(self, key: str) -> bool:
        return key in self.cache and datetime.utcnow() < self.cache_expiry.get(key, datetime.min)

    def _cache(self, key: str, value: List[Dict]):
        self.cache[key] = value
        self.cache_expiry[key] = datetime.utcnow() + timedelta(hours=2)

class AbuseCHIntelligence:
    def __init__(self):
        self.base_url = "https://urlhaus.abuse.ch/api"

    async def get_malware_urls(self) -> List[Dict]:
        try:
            async with aiohttp.ClientSession() as session:
                params = {"action": "get_url", "limit": 1000}
                async with session.get(self.base_url, params=params, timeout=60) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get('urls', [])
        except Exception as e:
            logger.error(f"Abuse.ch URLhaus error: {e}")

        return []

    async def get_ip_blocklist(self) -> List[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=60) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        return [line.strip() for line in text.split('\n') if line.strip() and not line.startswith('#')]
        except Exception as e:
            logger.error(f"Abuse.ch Feodo error: {e}")

        return []

class PhishTankIntelligence:
    def __init__(self):
        self.base_url = "https://data.phishtank.com/data/online-valid.csv.gz"

    async def get_phishing_urls(self) -> List[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, timeout=120) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        lines = content.split('\n')[1:]
                        return [line.split(',')[6] for line in lines if ',' in line and len(line.split(',')) > 6]
        except Exception as e:
            logger.error(f"PhishTank error: {e}")

        return []

class ThreatIntelAggregator:
    def __init__(self, otx_api_key: str = ""):
        self.otx = OTXIntelligence(otx_api_key) if otx_api_key else None
        self.abusech = AbuseCHIntelligence()
        self.phishtank = PhishTankIntelligence()
        self.indicators: Dict[str, set] = {
            'ip': set(),
            'domain': set(),
            'url': set(),
            'hash': set()
        }

    async def refresh_all(self):
        logger.info("refreshing threat intelligence feeds...")

        if self.otx:
            ipv4_indicators = await self.otx.get_indicators("IPv4")
            for ind in ipv4_indicators:
                self.indicators['ip'].add(ind.get('indicator'))

        malware_urls = await self.abusech.get_malware_urls()
        for url_data in malware_urls:
            self.indicators['url'].add(url_data.get('url'))

        phishing_urls = await self.phishtank.get_phishing_urls()
        self.indicators['url'].update(phishing_urls)

        logger.info(f"threat intel refresh complete: {sum(len(v) for v in self.indicators.values())} indicators")

    def check_ip(self, ip: str) -> Optional[Dict]:
        if ip in self.indicators['ip']:
            return {'type': 'ip', 'value': ip, 'source': 'threat_feed'}

        if self.otx:
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
                import requests
                resp = requests.get(url, headers=self.otx.headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('malicious'):
                        return {'type': 'ip', 'value': ip, 'source': 'otx', 'details': data}
            except:
                pass

        return None

    def check_url(self, url: str) -> Optional[Dict]:
        if url in self.indicators['url']:
            return {'type': 'url', 'value': url, 'source': 'threat_feed'}

        return None
