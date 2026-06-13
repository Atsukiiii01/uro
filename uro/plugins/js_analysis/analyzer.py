import logging
import requests
import re
from typing import Dict, List, Any

try:
    from uro import uro_rust_core # type: ignore
    RUST_CORE_ACTIVE = True
except ImportError:
    RUST_CORE_ACTIVE = False
    logging.warning("[!] uro_rust_core missing. Falling back to slow Python regex.")

class JSAnalyzer:
    def __init__(self, url: str, custom_headers: Dict[str, str] = None):
        self.url = url
        self.headers = custom_headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.timeout = 10

    def analyze(self) -> Dict[str, Any]:
        intel = {"paths": [], "secrets": []}
        try:
            response = requests.get(self.url, headers=self.headers, verify=False, timeout=self.timeout)
            if response.status_code != 200:
                return intel
            
            content = response.text

            if RUST_CORE_ACTIVE:
                try:
                    rust_paths, rust_secrets = uro_rust_core.extract_security_intel(content)
                    intel["paths"] = rust_paths
                    intel["secrets"] = [{"type": s[0], "value": s[1], "location": self.url} for s in rust_secrets]
                    return intel
                except Exception as e:
                    logging.error(f"[-] Rust core analysis crashed on {self.url}: {e}. Falling back to Python.")

            path_pattern = re.compile(r'(?:"|\')(((?:[a-zA-Z]{1,10}://|/)[^"\'\s]+|([a-zA-Z0-9_\-]+/)+[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9]+)?))(?:"|\')')
            secret_pattern = re.compile(r'(?i)(?:api_key|access_token|secret)[\s:=]+["\']([a-zA-Z0-9_\-]{16,})["\']')

            paths = path_pattern.findall(content)
            intel["paths"] = list(set([p[0] for p in paths]))

            secrets = secret_pattern.findall(content)
            intel["secrets"] = [{"type": "HEURISTIC_SECRET", "value": s, "location": self.url} for s in set(secrets)]

        except requests.exceptions.RequestException:
            pass
        except Exception as e:
            logging.error(f"[-] JS Analysis failed on {self.url}: {e}")

        return intel