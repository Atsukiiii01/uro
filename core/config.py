import yaml
import logging
import sys

class ConfigManager:
    _instance = None
    _config = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance

    def load_profile(self, profile_path: str):
        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                self._config = yaml.safe_load(f)
            logging.info(f"[*] Loaded operational profile: {self._config.get('program_name', 'Unknown Target')}")
        except FileNotFoundError:
            logging.error(f"[-] Profile not found at {profile_path}. Check your paths.")
            sys.exit(1)
        except yaml.YAMLError as e:
            logging.error(f"[-] Invalid YAML structure in {profile_path}: {e}")
            sys.exit(1)

    @property
    def headers(self) -> dict:
        return self._config.get("network_rules", {}).get("custom_headers", {})

    @property
    def rate_limit(self) -> int:
        return self._config.get("network_rules", {}).get("rate_limit_rps", 0)

    @property
    def scope_file(self) -> str:
        return self._config.get("ai_triage", {}).get("scope_file", "")