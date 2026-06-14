import logging
import subprocess
import json
import requests

class ReconEngine:
    def __init__(self, domain: str):
        self.domain = domain

    def _hacker_target(self) -> set:
        try:
            res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=10)
            if res.status_code == 200 and "error" not in res.text:
                return {line.split(',')[0] for line in res.text.split('\n') if line}
        except Exception:
            pass
        return set()

    def _subfinder(self) -> set:
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent", "-oJ"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            subdomains = set()
            for line in proc.stdout.splitlines():
                if line.strip():
                    subdomains.add(json.loads(line).get("host"))
            return subdomains
        except Exception as e:
            logging.warning(f"[!] Subfinder fallback execution skipped: {e}")
        return set()

    def run_all(self) -> set:
        logging.info(f"Querying HackerTarget for {self.domain}...")
        ht_subs = self._hacker_target()
        logging.info(f"Running subfinder for {self.domain}...")
        sf_subs = self._subfinder()
        total = ht_subs.union(sf_subs)
        logging.info(f"Total aggregated subdomains for {self.domain}: {len(total)}")
        return total