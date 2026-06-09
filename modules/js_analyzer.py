import re
import json
import os
import logging
import httpx
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Tuple
from core.config import ConfigManager

# Phase C: Safe Rust Integration with Graceful Degradation
try:
    import uro_rust_core
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    logging.warning("[!] uro_rust_core missing in JSAnalyzer. Falling back to slow Python regex.")

# Suppresses raw connection spam from drowning your terminal
logging.getLogger("httpx").setLevel(logging.WARNING)

class JSAnalyzer:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']')
        self.map_pattern = re.compile(r'//# sourceMappingURL=(.+\.map)')
        
        # Pure Python fallback compilation (Only executed if Rust engine is dead)
        if not RUST_AVAILABLE:
            self.fb_path = re.compile(r"(?:\"|')(/[a-zA-Z0-9_\-\.\?=&/]+)(?:\"|')")
            self.fb_jwt = re.compile(r"ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
            self.fb_aws = re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b")
            self.fb_tok = re.compile(r"(?i)(?:api_key|secret|token|authorization)[\"\s]*:[\s]*[\"']([a-zA-Z0-9\-_]{32,})[\"']")

        cfg = ConfigManager()
        self.headers = cfg.headers if cfg.headers else {"User-Agent": "Uro-Autonomous-OS/1.1"}
        parsed_url = urlparse(target_url)
        self.domain = parsed_url.netloc if parsed_url.netloc else "unknown_target"

    def _extract(self, raw_js: str) -> Tuple[List[str], List[tuple]]:
        """Routes to Rust engine if available, otherwise executes standard Python fallback."""
        if RUST_AVAILABLE:
            return uro_rust_core.extract_security_intel(raw_js)
            
        # Fallback Logic
        paths = list(set([p for p in self.fb_path.findall(raw_js) if '/' in p and len(p) > 2]))
        secrets = []
        secrets.extend([("JWT", m.group(0)) for m in self.fb_jwt.finditer(raw_js)])
        secrets.extend([("AWS_KEY", m.group(0)) for m in self.fb_aws.finditer(raw_js)])
        secrets.extend([("HIGH_ENTROPY_TOKEN", m.group(1)) for m in self.fb_tok.finditer(raw_js)])
        
        return paths, secrets

    def analyze(self) -> Dict[str, List]:
        intel = {"paths": [], "secrets": []}
        try:
            response = httpx.get(self.target_url, headers=self.headers, verify=False, timeout=15)
            scripts = self.script_pattern.findall(response.text)
            script_urls = list(set([urljoin(self.target_url, s) for s in scripts if ".js" in s]))
            
            if not script_urls:
                return intel

            logging.info(f"[JSAnalyzer] Found {len(script_urls)} JS bundles. Hunting for Source Maps...")
            
            with httpx.Client(headers=self.headers, verify=False, timeout=15) as client:
                for js_url in script_urls:
                    try:
                        js_resp = client.get(js_url)
                        raw_js = js_resp.text
                        
                        # Data piped through the dynamic router
                        paths, secrets = self._extract(raw_js)
                        self._append_intel(intel, paths, secrets, js_url)

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
                                    
                                    uncompiled_code = "\n".join(filter(None, sources_content))
                                    raw_paths, raw_secrets = self._extract(uncompiled_code)
                                    self._append_intel(intel, raw_paths, raw_secrets, map_url)

                    except Exception as e:
                        logging.debug(f"[JSAnalyzer] Failed to process {js_url}: {e}")

            intel["paths"] = list(set(intel["paths"]))
            unique_secrets = {s["value"]: s for s in intel["secrets"]}.values()
            intel["secrets"] = list(unique_secrets)
            
        except Exception as e:
            logging.error(f"[JSAnalyzer] Engine failure: {str(e)}")

        return intel

    def _dump_source_tree(self, sources: List[str], contents: List[str]):
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