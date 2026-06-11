import logging
import yaml
import os

class ConfigManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance.scope_file = None
            cls._instance.prober_threads = 10
        return cls._instance

    def load_profile(self, profile_path: str):
        if not os.path.exists(profile_path):
            logging.error(f"[-] Profile not found at {profile_path}. Check your paths.")
            return
        try:
            with open(profile_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
                self.scope_file = config_data.get("scope_file")
                self.prober_threads = config_data.get("threads", 10)
                logging.info(f"[*] Loaded operational profile: {config_data.get('name', 'Unknown Target')}")
        except Exception as e:
            logging.error(f"[-] Error loading profile {profile_path}: {e}")