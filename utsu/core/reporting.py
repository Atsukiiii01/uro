import os
import time
import logging
from urllib.parse import urlparse

class ReportManager:
    def __init__(self, workspace_dir: str = "workspace/reports"):
        self.workspace_dir = workspace_dir
        if not os.path.exists(self.workspace_dir):
            os.makedirs(self.workspace_dir, exist_ok=True)

    def save_triage_report(self, url: str, report_content: str) -> str:
        """Saves actionable AI triage reports to Markdown, dropping deprioritized noise."""
        if "[!] Status: Deprioritized" in report_content:
            return ""

        try:
            domain = urlparse(url).netloc.replace(":", "_")
            if not domain:
                domain = "unknown_target"
                
            timestamp = int(time.time())
            filename = f"H1_Triage_{domain}_{timestamp}.md"
            filepath = os.path.join(self.workspace_dir, filename)
            
            with open(filepath, "w") as f:
                f.write(report_content)
                
            logging.info(f"[+] High-value artifact saved: {filepath}")
            return filepath
        except Exception as e:
            logging.error(f"[-] Failed to write report artifact for {url}: {e}")
            return ""