import os
import logging
import yaml
from typing import Optional, Dict

class ConfigManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._load_defaults()
        return cls._instance

    def _load_defaults(self):
        self._load_env_file()
        self.db_path: str = os.getenv("DATABASE_PATH", "data/uro.db")
        self.ollama_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.ai_model: str = os.getenv("DEFAULT_AI_MODEL", "llama3.2")
        self.prober_threads: int = int(os.getenv("DEFAULT_PROBER_THREADS", "10"))
        self.rate_limit_rps: int = 10
        self.scope_file: Optional[str] = None
        self.profile_name: str = "Default Profile"
        self.custom_headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def _load_env_file(self):
        if os.path.exists(".env"):
            with open(".env", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        os.environ.setdefault(key.strip(), val.strip())

    def load_profile(self, profile_path: str):
        if not os.path.exists(profile_path):
            logging.error(f"[-] Profile layout missing at path: {profile_path}. Using system environment variables.")
            return

        try:
            with open(profile_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
                
                self.profile_name = config_data.get("name", "Unknown Target")
                
                # Sandbox the scope_file to prevent path traversal
                # Sandbox the scope_file to prevent path traversal
                raw_scope = config_data.get("scope_file")
                if raw_scope:
                    # Expand the ~ if it exists
                    raw_scope = os.path.expanduser(raw_scope)
                    
                    if os.path.isabs(raw_scope):
                        # If it's an absolute path (like /Users/aitoo/...), use it directly
                        self.scope_file = raw_scope
                    else:
                        # If it's relative, resolve it against the profile directory
                        base_dir = os.path.dirname(os.path.abspath(profile_path))
                        resolved = os.path.realpath(os.path.join(base_dir, raw_scope))
                        if resolved.startswith(base_dir):
                            self.scope_file = resolved
                        else:
                            logging.error("[-] SECURITY: scope_file path traversal attempt blocked.")
                
                if "threads" in config_data:
                    self.prober_threads = int(config_data["threads"])
                if "ai_model" in config_data:
                    self.ai_model = str(config_data["ai_model"])
                
                # Parse network rate limits
                network_rules = config_data.get("network_rules", {})
                if "rate_limit_rps" in network_rules:
                    self.rate_limit_rps = int(network_rules["rate_limit_rps"])
                
                # Extract arbitrary compliance headers dynamically
                if "custom_headers" in config_data and isinstance(config_data["custom_headers"], dict):
                    self.custom_headers.update(config_data["custom_headers"])
                    
                logging.info(f"[*] Activated operational profile: {self.profile_name}")
        except Exception as e:
            logging.error(f"[-] Operational profile parsing failure on {profile_path}: {e}")