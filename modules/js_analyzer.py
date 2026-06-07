import re
import json
import os
import logging
import httpx
from urllib.parse import urljoin, urlparse
from typing import Dict, List
import uro_rust_core
from core.config import ConfigManager  # Pulling the source of truth

# LEAVE THIS ALONE: Suppresses raw connection spam from drowning your terminal
logging.getLogger("httpx").setLevel(logging.WARNING)

class JSAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']')
        self.map_pattern = re.compile(r'//# sourceMappingURL=(.+\.map)')
        
        # 1. Query the Global Configuration Manager for your current headers
        cfg = ConfigManager()
        self.headers = cfg.headers if cfg.headers else {"User-Agent": "Uro-Autonomous-OS/1.1"}
        
        # Extract clean hostname for local directory structure paths
        parsed_url = urlparse(target_url)
        self.domain = parsed_url.netloc if parsed_url.netloc else "unknown_target"

    def analyze(self) -> Dict[str, List]:
        intel = {"paths": [], "secrets": []}
        try:
            # 2. Injected compliance headers into the initial page pull
            response = httpx.get(self.target_url, headers=self.headers, verify=False, timeout=15)
            scripts = self.script_pattern.findall(response.text)
            script_urls = list(set([urljoin(self.target_url, s) for s in scripts if ".js" in s]))
            
            if not script_urls:
                return intel

            logging.info(f"[JSAnalyzer] Found {len(script_urls)} JS bundles. Hunting for Source Maps...")
            
            # 3. Passed compliance headers into the concurrent client session
            with httpx.Client(headers=self.headers, verify=False, timeout=15) as client:
                for js_url in script_urls:
                    try:
                        js_resp = client.get(js_url)
                        raw_js = js_resp.text
                        
                        # Process compiled JavaScript inside the bare-metal Rust engine
                        paths, secrets = uro_rust_core.extract_security_intel(raw_js)
                        self._append_intel(intel, paths, secrets, js_url)

                        # Locate hidden Webpack Source Maps
                        map_match = self.map_pattern.search(raw_js)
                        if map_match:
                            map_path = map_match.group(1).strip()
                            map_url = urljoin(js_url, map_path)
                            
                            map_resp = client.get(map_url)
                            if map_resp.status_code == 200:
                                map_data = map_resp.json()
                                
                                sources = map_data.get("sources", [])
                                sources_content = map_data.get("sourcesContent", [])
                                
                                if sources and sources_content:
                                    logging.info(f"[JSAnalyzer] Exposed map verified. Reconstructing original source tree...")
                                    self._dump_source_tree(sources, sources_content)
                                    
                                    # Feed uncompiled raw developer code directly to the Rust engine
                                    uncompiled_code = "\n".join(filter(None, sources_content))
                                    raw_paths, raw_secrets = uro_rust_core.extract_security_intel(uncompiled_code)
                                    self._append_intel(intel, raw_paths, raw_secrets, map_url)

                    except Exception as e:
                        logging.debug(f"[JSAnalyzer] Failed to process {js_url}: {e}")

            # Deduplicate discoveries before writing to cache layers
            intel["paths"] = list(set(intel["paths"]))
            unique_secrets = {s["value"]: s for s in intel["secrets"]}.values()
            intel["secrets"] = list(unique_secrets)
            
        except Exception as e:
            logging.error(f"[JSAnalyzer] Engine failure: {str(e)}")

        return intel

    def _dump_source_tree(self, sources: List[str], contents: List[str]):
        """Reconstructs the original frontend deployment structure on the local disk."""
        base_dir = os.path.join("data", "unpacked", self.domain)
        
        for file_path, code_content in zip(sources, contents):
            if not file_path or not code_content:
                continue
                
            clean_path = file_path.replace("webpack:///", "").replace("../", "").split("?")[0]
            local_file_path = os.path.join(base_dir, clean_path)
            
            local_dir = os.path.dirname(local_file_path)
            os.makedirs(local_dir, exist_ok=True)
            
            try:
                with open(local_file_path, "w", encoding="utf-8") as f:
                    f.write(code_content)
            except Exception as e:
                logging.debug(f"[JSAnalyzer] Failed writing file {clean_path}: {e}")
                
        logging.info(f"[JSAnalyzer] Codebase successfully reconstructed at: {base_dir}")

    def _append_intel(self, intel: Dict, paths: List[str], secrets: List[tuple], source_url: str):
        intel["paths"].extend(paths)
        for key_type, secret_val in secrets:
            intel["secrets"].append({
                "type": key_type, 
                "value": secret_val, 
                "location": source_url
            })