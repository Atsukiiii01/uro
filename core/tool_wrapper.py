import subprocess
import shutil
import json
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class GoToolWrapper:
    def __init__(self):
        """Locates pre-installed ProjectDiscovery Go binaries, prioritizing absolute Homebrew paths to avoid Python library name collisions."""
        # Absolute pathing for Apple Silicon Homebrew installations
        homebrew_httpx = "/opt/homebrew/bin/httpx"
        homebrew_nuclei = "/opt/homebrew/bin/nuclei"

        if os.path.exists(homebrew_httpx):
            self.httpx_path = homebrew_httpx
        else:
            self.httpx_path = shutil.which("httpx")

        if os.path.exists(homebrew_nuclei):
            self.nuclei_path = homebrew_nuclei
        else:
            self.nuclei_path = shutil.which("nuclei")
        
        if not self.httpx_path or "site-packages" in self.httpx_path or "bin/httpx" not in self.httpx_path:
            # If it falls back to a python env binary, flag it
            logging.warning("[GoWrapper] ProjectDiscovery 'httpx' binary is being masked by a Python package. Ensure Go version is installed.")
        
        logging.info(f"[GoWrapper] Initialized httpx path: {self.httpx_path}")
        logging.info(f"[GoWrapper] Initialized nuclei path: {self.nuclei_path}")

    def run_httpx_probe(self, target_url: str) -> dict:
        """
        Executes Go 'httpx' to get precise technology fingerprints and titles.
        Bypasses python's socket limitations using native Go network concurrency.
        """
        if not self.httpx_path:
            return {"error": "httpx binary missing"}

        cmd = [self.httpx_path, "-u", target_url, "-title", "-tech-detect", "-status-code", "-json", "-silent"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout:
                return json.loads(result.stdout.strip())
        except subprocess.TimeoutExpired:
            logging.error(f"[GoWrapper] httpx timed out scanning {target_url}")
        except Exception as e:
            logging.error(f"[GoWrapper] httpx error: {str(e)}")
            
        return {}

    def run_nuclei_scan(self, target_url: str, tags: str = "tech") -> list:
        """
        Executes Go 'nuclei' engine targeting low-impact passive validation profiles.
        Returns verified signature matches to destroy LLM hallucinations.
        """
        if not self.nuclei_path:
            return []

        # We keep scans strictly focused using designated template tags to optimize runtime
        cmd = [
            self.nuclei_path, 
            "-target", target_url, 
            "-tags", tags, 
            "-severity", "low,medium,high,critical",
            "-jsonl", 
            "-silent"
        ]
        
        findings = []
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.stdout:
                for line in result.stdout.splitlines():
                    if line.strip():
                        findings.append(json.loads(line.strip()))
        except subprocess.TimeoutExpired:
            logging.error(f"[GoWrapper] nuclei timed out scanning {target_url}")
        except Exception as e:
            logging.error(f"[GoWrapper] nuclei error: {str(e)}")
            
        return findings