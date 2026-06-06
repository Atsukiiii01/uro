import re
import logging
import httpx
from urllib.parse import urljoin
from typing import Dict, List
import uro_rust_core  # Your newly compiled C-extension

logging.getLogger("httpx").setLevel(logging.WARNING)

class JSAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        # We use Python solely to grab the initial <script src> tags
        self.script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']')

    def analyze(self) -> Dict[str, List]:
        intel = {"paths": [], "secrets": []}
        try:
            # 1. Fetch the main HTML DOM
            response = httpx.get(self.target_url, verify=False, timeout=15)
            scripts = self.script_pattern.findall(response.text)
            
            # 2. Build absolute URLs for the Javascript bundles
            script_urls = list(set([urljoin(self.target_url, s) for s in scripts if ".js" in s]))
            
            if not script_urls:
                logging.info(f"[JSAnalyzer] No external scripts found on {self.target_url}")
                return intel

            logging.info(f"[JSAnalyzer] Found {len(script_urls)} JS bundles. Offloading to Rust...")
            
            # 3. Download bundles and execute bare-metal Rust parsing
            with httpx.Client(verify=False, timeout=15) as client:
                for js_url in script_urls:
                    try:
                        js_resp = client.get(js_url)
                        raw_js = js_resp.text
                        
                        # Drop down to C-level execution speeds
                        paths, secrets = uro_rust_core.extract_security_intel(raw_js)
                        
                        intel["paths"].extend(paths)
                        for key_type, secret_val in secrets:
                            intel["secrets"].append({
                                "type": key_type, 
                                "value": secret_val, 
                                "location": js_url
                            })
                            
                    except Exception as e:
                        logging.debug(f"[JSAnalyzer] Failed to process {js_url}: {e}")

            # 4. Final Deduplication
            intel["paths"] = list(set(intel["paths"]))
            
            seen_secrets = set()
            unique_secrets = []
            for s in intel["secrets"]:
                if s["value"] not in seen_secrets:
                    seen_secrets.add(s["value"])
                    unique_secrets.append(s)
            intel["secrets"] = unique_secrets

            logging.info(f"[JSAnalyzer] Rust engine extracted {len(intel['paths'])} routes and {len(intel['secrets'])} secrets.")
            
        except Exception as e:
            logging.error(f"[JSAnalyzer] Engine failure on {self.target_url}: {str(e)}")

        return intel