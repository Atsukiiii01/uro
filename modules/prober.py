import asyncio
import httpx
import logging
import re
from typing import Dict, List, Tuple
from core.config import ConfigManager

class LiveProber:
    def __init__(self, threads: int = 10):
        cfg = ConfigManager()
        self.threads = threads
        self.headers = cfg.headers if cfg.headers else {"User-Agent": "Uro-Autonomous-OS/1.1"}
        
        rps = cfg.rate_limit
        self.rate_limit_delay = (1.0 / rps) if rps > 0 else 0
        self.title_re = re.compile(r'<title>(.*?)</title>', re.IGNORECASE)

    async def _probe(self, client: httpx.AsyncClient, subdomain_id: int, target: str) -> Dict:
        """Probes a target with aggressive timeouts to prevent getting stuck in WAF tarpits."""
        # HTTPS check first
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
        except (httpx.RequestError, httpx.TimeoutException):
            # Immediate HTTP Fallback if HTTPS drops or times out
            url = f"http://{target}"
            try:
                response = await client.get(url)
                return {
                    "subdomain_id": subdomain_id,
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "title": self._extract_title(response.text)
                }
            except (httpx.RequestError, httpx.TimeoutException):
                return None

    def _extract_title(self, html: str) -> str:
        match = self.title_re.search(html)
        return match.group(1).strip() if match else "No Title"

    async def _worker(self, queue: asyncio.Queue, client: httpx.AsyncClient, results: List[Dict], progress: Dict):
        """Worker loop that pulls sequentially from the queue, preserving true rate-limits."""
        while not queue.empty():
            try:
                sub_id, sub_name = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            if self.rate_limit_delay > 0:
                await asyncio.sleep(self.rate_limit_delay)

            res = await self._probe(client, sub_id, sub_name)
            if res:
                results.append(res)
            
            # Incremental progress feedback loop
            progress["count"] += 1
            if progress["count"] % 50 == 0:
                logging.info(f"[*] Prober Progress: Checked {progress['count']}/{progress['total']} assets...")
            
            queue.task_done()

    async def _run_concurrently(self, assets: Dict[int, str]) -> List[Dict]:
        if not assets:
            return []

        # Populate the asynchronous FIFO task queue
        queue = asyncio.Queue()
        for item in assets.items():
            queue.put_nowait(item)

        results = []
        progress = {"count": 0, "total": len(assets)}
        
        # Hardened Timeouts: 3s connect, 3s read, 6s total max per handshake attempt
        timeout = httpx.Timeout(timeout=6.0, connect=3.0, read=3.0)
        limits = httpx.Limits(max_connections=self.threads, max_keepalive_connections=self.threads)
        
        async with httpx.AsyncClient(
            headers=self.headers, 
            verify=False, 
            limits=limits, 
            timeout=timeout, 
            follow_redirects=True
        ) as client:
            # Spawn bounded worker allocation matching thread budget
            workers = [
                asyncio.create_task(self._worker(queue, client, results, progress))
                for _ in range(min(self.threads, len(assets)))
            ]
            await asyncio.gather(*workers)
            
        return results

    def run(self, assets: Dict[int, str]) -> List[Dict]:
        logging.info(f"[*] Launching Bounded Worker Prober against {len(assets)} targets.")
        return asyncio.run(self._run_concurrently(assets))