import logging
import requests
import urllib3
import socket
import ipaddress
import time
from urllib.parse import urlparse
from threading import Semaphore
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LiveProber:
    def __init__(self, threads: int = 10, rps: int = 10):
        self.threads = threads
        self.rps = rps
        self._rate_semaphore = Semaphore(self.rps)
        self._last_request_time = 0.0
        self.timeout = 7
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    def _rate_limited_get(self, url: str, host_header: str):
        """Executes the request respecting the strict rate limit."""
        with self._rate_semaphore:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < 1.0 / self.rps:
                time.sleep((1.0 / self.rps) - elapsed)
            self._last_request_time = time.monotonic()
            
            headers = self.headers.copy()
            headers["Host"] = host_header
            return requests.get(url, headers=headers, verify=False, timeout=self.timeout, allow_redirects=True)

    def _probe_single(self, subdomain_id: int, subdomain: str) -> Dict:
        """Atomic resolution and probing to prevent DNS rebinding SSRF."""
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                hostname = urlparse(url).hostname
                ip_str = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(ip_str)
                
                if not ip_obj.is_global:
                    continue
                
                # Build IP-direct URL to prevent TOCTOU race condition
                ip_url = url.replace(hostname, ip_str)
                
                response = self._rate_limited_get(ip_url, host_header=hostname)
                
                title = ""
                if "<title>" in response.text.lower():
                    try:
                        title = response.text.split("<title>")[1].split("</title>")[0][:50]
                    except IndexError:
                        pass

                return {
                    "subdomain_id": subdomain_id,
                    "url": url, # Store original URL for logic, but probed via IP
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "title": title.strip()
                }

            except (requests.exceptions.RequestException, socket.gaierror, ValueError):
                continue
        return {}

    def run(self, targets: Dict[int, str]) -> List[Dict]:
        live_services = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {executor.submit(self._probe_single, sub_id, sub): sub for sub_id, sub in targets.items()}
            for future in as_completed(future_to_target):
                result = future.result()
                if result:
                    live_services.append(result)
        return live_services