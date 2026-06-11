import json
import requests
import logging

class TriageAgent:
    def __init__(self, endpoint: str = "http://127.0.0.1:11434"):
        self.endpoint = endpoint

    def run(self, web_service_id: int, url: str, scope_rules: str) -> str:
        prompt = f"Triage target security state for: {url}\nRules context:\n{scope_rules}"
        try:
            payload = {"model": "llama3", "prompt": prompt, "stream": False}
            res = requests.post(f"{self.endpoint}/api/generate", json=payload, timeout=45)
            if res.status_code == 200:
                return res.json().get("response", "No analysis returned.")
        except Exception as e:
            logging.error(f"[-] Ollama direct context request failed: {e}")
        return "Surface analysis offline or connection timed out."