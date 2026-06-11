import os
import logging
import yaml
from typing import Optional

class ConfigManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._load_defaults()
        return cls._instance

    def _load_defaults(self):
        """Loads baseline parameters from environment variables or safe fallbacks."""
        self._load_env_file()

        self.db_path: str = os.getenv("DATABASE_PATH", "data/uro.db")
        self.ollama_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.ai_model: str = os.getenv("DEFAULT_AI_MODEL", "llama3.2")
        self.prober_threads: int = int(os.getenv("DEFAULT_PROBER_THREADS", "10"))
        self.scope_file: Optional[str] = None
        self.profile_name: str = "Default Profile"

    def _load_env_file(self):
        """Rudimentary .env parsing helper to avoid external dependency requirements."""
        if os.path.exists(".env"):
            with open(".env", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        os.environ.setdefault(key.strip(), val.strip())

    def load_profile(self, profile_path: str):
        """Overlays runtime variables parsed directly from a target YAML profile."""
        if not os.path.exists(profile_path):
            logging.error(f"[-] Profile layout missing at path: {profile_path}. Using system environment variables.")
            return

        try:
            with open(profile_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
                
                self.profile_name = config_data.get("name", "Unknown Target")
                self.scope_file = config_data.get("scope_file")
                
                if "threads" in config_data:
                    self.prober_threads = int(config_data["threads"])
                if "ai_model" in config_data:
                    self.ai_model = str(config_data["ai_model"])
                    
                logging.info(f"[*] Activated operational profile: {self.profile_name}")
        except Exception as e:
            logging.error(f"[-] Operational profile parsing failure on {profile_path}: {e}")