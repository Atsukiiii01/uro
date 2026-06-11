import logging
import socket
import ipaddress
import re
import requests
import urllib3
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LiveProber:
    def __init__(self, threads: int = 10):
        self.threads = threads
        self.timeout = 7

    def _is_safe_target(self, url: str) -> bool:
        try:
            hostname = urlparse(url).hostname
            if not hostname: 
                return False
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_global
        except (socket.gaierror, ValueError):
            return False

    def _get_title(self, html: str) -> str:
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else "No Title"

    def _probe_single(self, subdomain_id: int, subdomain: str) -> Optional[Dict[str, Any]]:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            if not self._is_safe_target(url):
                continue
            try:
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    verify=False, 
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                return {
                    "subdomain_id": subdomain_id,
                    "url": response.url,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "title": self._get_title(response.text)
                }
            except requests.RequestException:
                continue
        return None

    def run(self, assets: Dict[int, str]) -> List[Dict[str, Any]]:
        live_services = []
        total = len(assets)
        completed = 0
        logging.info(f"[*] Launching Bounded Worker Prober against {total} targets.")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_asset = {
                executor.submit(self._probe_single, sub_id, sub): (sub_id, sub) 
                for sub_id, sub in assets.items()
            }
            for future in as_completed(future_to_asset):
                completed += 1
                if completed % 50 == 0 or completed == total:
                    logging.info(f"[*] Prober Progress: Checked {completed}/{total} assets...")
                try:
                    result = future.result()
                    if result:
                        live_services.append(result)
                except Exception as e:
                    _, sub = future_to_asset[future]
                    logging.error(f"[-] Prober thread crashed on {sub}: {e}")
        return live_services