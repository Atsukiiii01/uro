import requests
import re
import logging
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class JSAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
        # Regex to locate clean relative and relative-absolute endpoints
        self.path_regex = re.compile(r'(?:"|")(/[a-zA-Z0-9_\-\.\/]{2,100})(?:"|")')
        
        # Basic signatures to uncover leaky configs or sensitive data fields
        self.secret_signatures = {
            "Generic API Key": re.compile(r'(?i)(?:key|api_key|auth|secret|token)(?:["\']\s*:\s*|["\']\s*=\s*|["\'])([a-zA-Z0-9_\-]{16,64})'),
            "Bearer JWT": re.compile(r'eyJhbGciOi[a-zA-Z0-9-_=]+\.[a-zA-Z0-9-_=]+\.?[a-zA-Z0-9-_=]*'),
            "Firebase URL": re.compile(r'https://[a-zA-Z0-9-.]+.firebaseio.com')
        }

    def extract_js_links(self) -> Set[str]:
        """Parses script tags inside the HTML payload."""
        js_links = set()
        try:
            res = requests.get(self.target_url, headers=self.headers, timeout=7, verify=False)
            if res.status_code != 200:
                return js_links
            
            # Simple, light extraction regex to avoid heavy BS4 processing
            script_srcs = re.findall(r'<script[^>]+src=["\'](.*?)["\']', res.text, re.IGNORECASE)
            for src in script_srcs:
                # Ensure relative paths convert cleanly to absolute URLs
                absolute_url = urljoin(self.target_url, src)
                # Ensure we only scan scripts belonging to our target ecosystem, not third-party tracking scripts
                if urlparse(absolute_url).netloc == urlparse(self.target_url).netloc:
                    js_links.add(absolute_url)
        except Exception as e:
            logging.debug(f"Error reading root HTML lines from {self.target_url}: {str(e)}")
        return js_links

    def scan_js_file(self, js_url: str) -> Dict[str, List[str]]:
        """Downloads a script and processes its AST code string for patterns."""
        findings = {"paths": [], "secrets": []}
        try:
            res = requests.get(js_url, headers=self.headers, timeout=7, verify=False)
            if res.status_code != 200:
                return findings

            content = res.text

            # 1. Path Extraction
            paths = self.path_regex.findall(content)
            for p in paths:
                # Filter out obvious false positives like web asset extensions or formatting artifacts
                if not p.endswith(('.css', '.png', '.jpg', '.jpeg', '.svg', '.woff', '.json')):
                    findings["paths"].append(p)

            # 2. Secret Pattern Scanning
            for label, pattern in self.secret_signatures.items():
                matches = pattern.findall(content)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    findings["secrets"].append({"type": label, "value": match})

        except Exception as e:
            logging.debug(f"Failed scanning script resource {js_url}: {str(e)}")
        return findings

    def analyze(self) -> Dict:
        """Orchestrates parallel scanning across all internal script discoveries."""
        js_urls = self.extract_js_links()
        all_paths = set()
        all_secrets = []

        if not js_urls:
            return {"paths": [], "secrets": []}

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self.scan_js_file, url): url for url in js_urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                data = future.result()
                
                for p in data["paths"]:
                    all_paths.add(p)
                for sec in data["secrets"]:
                    sec["location"] = url
                    all_secrets.append(sec)

        return {
            "paths": list(all_paths),
            "secrets": all_secrets
        }