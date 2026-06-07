import asyncio
import httpx
import logging
from typing import Dict, List
from core.config import ConfigManager

class LiveProber:
    def __init__(self, threads: int = 10):
        cfg = ConfigManager()
        self.threads = threads
        self.headers = cfg.headers if cfg.headers else {"User-Agent": "Uro-Autonomous-OS/1.1"}
        
        rps = cfg.rate_limit
        # If RPS is 10, delay is 0.1s. If RPS is 0 (unlimited), delay is 0.
        self.rate_limit_delay = (1.0 / rps) if rps > 0 else 0

    async def _probe(self, client: httpx.AsyncClient, subdomain_id: int, target: str) -> Dict:
        if self.rate_limit_delay > 0:
            await asyncio.sleep(self.rate_limit_delay)
            
        url = f"https://{target}"
        try:
            response = await client.get(url)
            return {
                "subdomain_id": subdomain_id,
                "url": str(response.url),
                "status_code": response.status_code,
                "content_length": len(response.content),
                "title": self._extract_title(response.text)
            }
        except httpx.RequestError:
            try:
                url = f"http://{target}"
                response = await client.get(url)
                return {
                    "subdomain_id": subdomain_id,
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "title": self._extract_title(response.text)
                }
            except httpx.RequestError:
                return None

    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else "No Title"

    async def _run_concurrently(self, assets: Dict[int, str]) -> List[Dict]:
        limits = httpx.Limits(max_connections=self.threads, max_keepalive_connections=self.threads)
        timeout = httpx.Timeout(15.0)
        
        async with httpx.AsyncClient(headers=self.headers, verify=False, limits=limits, timeout=timeout, follow_redirects=True) as client:
            tasks = [self._probe(client, sub_id, sub_name) for sub_id, sub_name in assets.items()]
            results = await asyncio.gather(*tasks)
            return [r for r in results if r is not None]

    def run(self, assets: Dict[int, str]) -> List[Dict]:
        logging.info(f"[*] Launching LiveProber (Strict Compliance Enforced)")
        return asyncio.run(self._run_concurrently(assets))