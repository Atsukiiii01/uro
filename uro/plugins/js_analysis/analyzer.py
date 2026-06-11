import logging
import re
import requests
import urllib3
from typing import Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from uro import uro_rust_core # type: ignore
    RUST_CORE_ACTIVE = True
except ImportError:
    RUST_CORE_ACTIVE = False

class JSAnalyzer:
    def __init__(self, url: str):
        self.url = url
        self.timeout = 10
        self.path_pattern = re.compile(r'["\'](/[a-zA-Z0-9_/?&\-=.]+)["\']')
        self.secret_pattern = re.compile(r'(?i)(?:api_key|apikey|secret|token|bearer|password)[\s:=]+["\']([a-zA-Z0-9_\-\.]{16,})["\']')

    def analyze(self) -> Dict[str, Any]:
        intel: Dict[str, Any] = {"paths": [], "secrets": []}
        try:
            response = requests.get(
                self.url, 
                timeout=self.timeout, 
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if response.status_code != 200:
                return intel
            content = response.text

            if RUST_CORE_ACTIVE:
                try:
                    rust_result = uro_rust_core.analyze_content(content, self.url)
                    if isinstance(rust_result, dict):
                        intel["paths"].extend(rust_result.get("paths", []))
                        intel["secrets"].extend(rust_result.get("secrets", []))
                    return intel
                except Exception as e:
                    logging.error(f"[-] Rust engine failure on {self.url}: {e}")

            intel["paths"] = list(set(self.path_pattern.findall(content)))
            for secret in set(self.secret_pattern.findall(content)):
                if len(secret) > 15:
                    intel["secrets"].append({"type": "Generic_Secret", "value": secret, "location": self.url})
            return intel
        except requests.RequestException:
            return intel