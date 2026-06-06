import re
import json
import logging
import httpx
from urllib.parse import urljoin
from typing import Dict, List
import uro_rust_core

logging.getLogger("httpx").setLevel(logging.WARNING)

class JSAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']')
        # Regex to hunt for exposed Source Maps at the bottom of minified files
        self.map_pattern = re.compile(r'//# sourceMappingURL=(.+\.map)')

    def analyze(self) -> Dict[str, List]:
        intel = {"paths": [], "secrets": []}
        try:
            response = httpx.get(self.target_url, verify=False, timeout=15)
            scripts = self.script_pattern.findall(response.text)
            script_urls = list(set([urljoin(self.target_url, s) for s in scripts if ".js" in s]))
            
            if not script_urls:
                logging.info(f"[JSAnalyzer] No external scripts found on {self.target_url}")
                return intel

            logging.info(f"[JSAnalyzer] Found {len(script_urls)} JS bundles. Hunting for Source Maps...")
            
            with httpx.Client(verify=False, timeout=15) as client:
                for js_url in script_urls:
                    try:
                        js_resp = client.get(js_url)
                        raw_js = js_resp.text
                        
                        # 1. Parse the compiled JS using Rust
                        paths, secrets = uro_rust_core.extract_security_intel(raw_js)
                        self._append_intel(intel, paths, secrets, js_url)

                        # 2. Hunt for Developer Source Maps
                        map_match = self.map_pattern.search(raw_js)
                        if map_match:
                            map_path = map_match.group(1).strip()
                            map_url = urljoin(js_url, map_path)
                            logging.info(f"[JSAnalyzer] Source Map exposed! Downloading: {map_url}")
                            
                            map_resp = client.get(map_url)
                            if map_resp.status_code == 200:
                                map_data = map_resp.json()
                                sources_content = map_data.get("sourcesContent", [])
                                
                                if sources_content:
                                    logging.info(f"[JSAnalyzer] Unpacking {len(sources_content)} raw developer files from map...")
                                    # Concatenate the original uncompiled source tree
                                    uncompiled_code = "\n".join(filter(None, sources_content))
                                    
                                    # 3. Parse the highly-sensitive uncompiled code using Rust
                                    raw_paths, raw_secrets = uro_rust_core.extract_security_intel(uncompiled_code)
                                    self._append_intel(intel, raw_paths, raw_secrets, map_url)

                    except Exception as e:
                        logging.debug(f"[JSAnalyzer] Failed to process {js_url}: {e}")

            # 4. Final Deduplication
            intel["paths"] = list(set(intel["paths"]))
            unique_secrets = {s["value"]: s for s in intel["secrets"]}.values()
            intel["secrets"] = list(unique_secrets)

            logging.info(f"[JSAnalyzer] Engine extracted {len(intel['paths'])} routes and {len(intel['secrets'])} secrets.")
            
        except Exception as e:
            logging.error(f"[JSAnalyzer] Engine failure on {self.target_url}: {str(e)}")

        return intel

    def _append_intel(self, intel: Dict, paths: List[str], secrets: List[tuple], source_url: str):
        """Helper to structure Rust outputs into the intel dictionary."""
        intel["paths"].extend(paths)
        for key_type, secret_val in secrets:
            intel["secrets"].append({
                "type": key_type, 
                "value": secret_val, 
                "location": source_url
            })