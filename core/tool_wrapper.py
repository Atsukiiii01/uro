import subprocess
import json
import logging
import shutil
from typing import List, Dict
from core.config import ConfigManager

class GoWrapper:
    def __init__(self):
        cfg = ConfigManager()
        self.cmd_headers = []
        for key, value in cfg.headers.items():
            self.cmd_headers.extend(["-H", f"{key}: {value}"])
        rps = cfg.rate_limit
        self.rate_limit_args = ["-rl", str(rps)] if rps > 0 else []

    def run_httpx(self, target_url: str) -> List[str]:
        if not shutil.which("httpx"):
            logging.error("[-] httpx binary missing from system PATH.")
            return []
            
        cmd = ["httpx", "-silent", "-u", target_url, "-tech-detect", "-json"]
        cmd.extend(self.cmd_headers)
        cmd.extend(self.rate_limit_args)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logging.warning(f"[!] httpx returned error code: {result.returncode}")
                return []
            
            stack = []
            for line in result.stdout.strip().split('\n'):
                if not line: continue
                try:
                    data = json.loads(line)
                    # FIXED: Account for modern 'tech' key and fallback to legacy string array
                    if "tech" in data and data["tech"]:
                        stack.extend(data["tech"])
                    elif "technologies" in data and data["technologies"]:
                        stack.extend(data["technologies"])
                except json.JSONDecodeError:
                    continue
            return list(set(stack))
        except Exception as e:
            logging.error(f"[-] httpx execution failed: {e}")
            return []

    def run_nuclei(self, target_url: str) -> List[Dict]:
        if not shutil.which("nuclei"):
            logging.error("[-] nuclei binary missing from system PATH.")
            return []
            
        # OPTIMIZED: Bound the templates to critical/high to prevent rate-limiting hangs during triage
        cmd = ["nuclei", "-u", target_url, "-silent", "-jsonl", "-severity", "critical,high"]
        cmd.extend(self.cmd_headers)
        cmd.extend(self.rate_limit_args)
        
        try:
            logging.info("[Supervisor] Launching optimized signature scanning matrix...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode != 0 and not result.stdout:
                logging.error(f"[!] Nuclei execution dropped error: {result.stderr}")
                return []
                
            vulns = []
            for line in result.stdout.strip().split('\n'):
                if not line: continue
                try:
                    data = json.loads(line)
                    vulns.append({
                        "template_id": data.get("template-id"),
                        "severity": data.get("info", {}).get("severity"),
                        "name": data.get("info", {}).get("name"),
                        "matched": data.get("matched-at")
                    })
                except json.JSONDecodeError:
                    continue
            return vulns
        except Exception as e:
            logging.error(f"[-] nuclei execution failed: {e}")
            return []