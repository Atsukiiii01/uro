import requests
import logging
import json
import subprocess
import shutil
from typing import Set

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ReconEngine:
    def __init__(self, domain: str):
        self.domain = domain
        self.headers = {'User-Agent': 'uro-bugbounty-os'}

    def fetch_from_crtsh(self) -> Set[str]:
        logging.info(f"Querying crt.sh for {self.domain}...")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        subdomains = set()
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        clean_name = name.strip().lower()
                        if clean_name.startswith('*.'):
                            clean_name = clean_name[2:]
                        if clean_name.endswith(self.domain) and clean_name != self.domain:
                            subdomains.add(clean_name)
                logging.info(f"Found {len(subdomains)} unique subdomains from crt.sh")
            else:
                logging.warning(f"crt.sh returned status code {response.status_code}")
        except Exception as e:
            logging.warning(f"Failed fetching from crt.sh: {str(e)}")
            
        return subdomains

    def fetch_from_hackertarget(self) -> Set[str]:
        logging.info(f"Querying HackerTarget for {self.domain}...")
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        subdomains = set()
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                for line in response.text.splitlines():
                    parts = line.split(',')
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub.endswith(self.domain) and sub != self.domain:
                            subdomains.add(sub)
                logging.info(f"Found {len(subdomains)} unique subdomains from HackerTarget")
            else:
                logging.warning(f"HackerTarget returned status code {response.status_code}")
        except Exception as e:
            logging.warning(f"Failed fetching from HackerTarget: {str(e)}")
            
        return subdomains

    def fetch_from_subfinder(self) -> Set[str]:
        subdomains = set()
        if not shutil.which("subfinder"):
            logging.warning("subfinder binary not found in PATH. Skipping local execution.")
            return subdomains

        logging.info(f"Running subfinder for {self.domain}...")
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent", "-nc"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            for line in result.stdout.splitlines():
                clean_name = line.strip().lower()
                if clean_name and clean_name != self.domain:
                    subdomains.add(clean_name)
            logging.info(f"Found {len(subdomains)} unique subdomains from subfinder")
        except subprocess.CalledProcessError as e:
            logging.error(f"Subfinder execution failed: {e.stderr}")
        except Exception as e:
            logging.error(f"Unexpected error running subfinder: {str(e)}")

        return subdomains

    def run_all(self) -> Set[str]:
        """Combines all passive sources."""
        crt_subs = self.fetch_from_crtsh()
        ht_subs = self.fetch_from_hackertarget()
        sf_subs = self.fetch_from_subfinder()
        
        all_subs = crt_subs.union(ht_subs).union(sf_subs)
        logging.info(f"Total aggregated subdomains for {self.domain}: {len(all_subs)}")
        return all_subs