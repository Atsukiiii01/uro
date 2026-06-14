import os
from datetime import datetime

class ReportManager:
    def __init__(self, workspace_dir="workspace"):
        self.workspace_dir = workspace_dir
        os.makedirs(self.workspace_dir, exist_ok=True)
        
        # Master file for the hunt phase
        self.master_hunt_log = os.path.join(self.workspace_dir, "master_hunt_report.md")

    def save_triage_report(self, url: str, report_content: str):
        """Appends the AI triage report to a single, consolidated master file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.master_hunt_log, "a", encoding="utf-8") as f:
            f.write(f"## Target Triaged at {timestamp}\n")
            f.write(f"{report_content}\n")
            f.write("---\n\n")

    def save_scan_targets(self, target_domain: str, active_urls: list) -> str:
        """Saves a clean, flat list of live URLs to a single text file for easy pipelining."""
        sanitized_domain = target_domain.replace(".", "_")
        file_path = os.path.join(self.workspace_dir, f"{sanitized_domain}_live_targets.txt")
        
        with open(file_path, "w", encoding="utf-8") as f:
            for url in active_urls:
                f.write(f"{url}\n")
                
        return file_path