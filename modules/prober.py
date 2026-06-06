import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LiveProber:
    def __init__(self, threads: int = 20):
        self.threads = threads
        self.timeout = 5
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

    def _extract_title(self, html: str) -> str:
        """Quick regex to grab the HTML page title without importing heavy parsers like BS4."""
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()[:100]
        return "No Title"

    def probe_url(self, url: str) -> Optional[Dict]:
        """Probes a single URL to verify if it is alive."""
        try:
            # We use verify=False to ignore self-signed SSL errors common in bug bounties
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=True)
            return {
                "url": response.url, # Captures final URL if redirected
                "status_code": response.status_code,
                "content_length": len(response.content),
                "title": self._extract_title(response.text)
            }
        except requests.RequestException:
            return None

    def probe_subdomain(self, subdomain: str) -> list:
        """Checks both HTTP and HTTPS targets for a subdomain."""
        results = []
        for protocol in ["https://", "http://"]:
            res = self.probe_url(f"{protocol}{subdomain}")
            if res:
                results.append(res)
                # If HTTPS works cleanly, we often don't want to choke on HTTP noise,
                # but for bug bounty, sometimes HTTP hosts entirely different apps. We keep both.
        return results

    def run(self, subdomains_dict: Dict[int, str]) -> list:
        """
        Accepts a dict of {subdomain_id: subdomain_string}
        Runs concurrent workers to probe them efficiently.
        """
        live_targets = []
        logging.info(f"Starting live probe on {len(subdomains_dict)} subdomains using {self.threads} threads...")

        # Disable annoying insecure request warnings from urllib3
        requests.packages.urllib3.disable_warnings()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Map futures to their database IDs
            future_to_subid = {
                executor.submit(self.probe_subdomain, sub_str): sub_id 
                for sub_id, sub_str in subdomains_dict.items()
            }

            for future in as_completed(future_to_subid):
                sub_id = future_to_subid[future]
                try:
                    probe_results = future.result()
                    for res in probe_results:
                        res["subdomain_id"] = sub_id
                        live_targets.append(res)
                        logging.info(f"[LIVE] {res['url']} [{res['status_code']}] ({res['title']})")
                except Exception as e:
                    logging.error(f"Error executing probe for sub ID {sub_id}: {str(e)}")

        return live_targets