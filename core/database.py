import sqlite3
import logging
import os
from datetime import datetime
from typing import List, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DeltaDB:
    def __init__(self, db_path: str = "data/uro.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Creates the minimalist tables required for Delta tracking."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain_id INTEGER,
                    subdomain TEXT UNIQUE NOT NULL,
                    is_scanned BOOLEAN DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(domain_id) REFERENCES domains(id)
                )
            ''')
            # NEW: Track active HTTP/HTTPS endpoints found on subdomains
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subdomain_id INTEGER,
                    url TEXT UNIQUE NOT NULL,
                    status_code INTEGER,
                    content_length INTEGER,
                    title TEXT,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
                )
            ''')
            conn.commit()
            logging.info("Database initialized.")

            # Track endpoints discovered inside JS or crawled links
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    web_service_id INTEGER,
                    path TEXT NOT NULL,
                    source TEXT NOT NULL, -- e.g., "js_file", "html_crawl"
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(web_service_id, path),
                    FOREIGN KEY(web_service_id) REFERENCES web_services(id)
                )
            ''')
            
            # Track raw secrets or keys found during analysis
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS leaked_secrets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    web_service_id INTEGER,
                    type TEXT NOT NULL, -- e.g., "API_Key", "JWT", "Firebase"
                    secret_value TEXT NOT NULL,
                    location TEXT NOT NULL, -- URL of the specific JS file
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(web_service_id, secret_value),
                    FOREIGN KEY(web_service_id) REFERENCES web_services(id)
                )
            ''')

    def add_endpoint(self, web_service_id: int, path: str, source: str):
        """Stores a unique discovered path relative to a web service."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO endpoints (web_service_id, path, source)
                VALUES (?, ?, ?)
            ''', (web_service_id, path, source))
            conn.commit()

    def add_secret(self, web_service_id: int, secret_type: str, value: str, location: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO leaked_secrets (web_service_id, type, secret_value, location, discovered_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (web_service_id, secret_type, value, location))
            conn.commit()

    def add_web_service(self, subdomain_id: int, url: str, status_code: int, content_length: int, title: str):
        """Stores a verified live web asset."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO web_services (subdomain_id, url, status_code, content_length, title)
                VALUES (?, ?, ?, ?, ?)
            ''', (subdomain_id, url, status_code, content_length, title))
            conn.commit()

    def add_domain(self, domain: str) -> int:
        """Adds a root domain. Returns the domain ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO domains (domain) VALUES (?)', (domain,))
            cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
            return cursor.fetchone()[0]

    def process_subdomain(self, domain_id: int, subdomain: str) -> bool:
        """
        The core of the Delta Engine.
        Returns True if the subdomain is brand new.
        Returns False if we already knew about it (just updates last_seen).
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if it exists
            cursor.execute('SELECT id FROM subdomains WHERE subdomain = ?', (subdomain,))
            result = cursor.fetchone()
            
            if result:
                # It exists. Not a delta. Just update the last_seen timestamp.
                cursor.execute('''
                    UPDATE subdomains 
                    SET last_seen = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (result[0],))
                return False
            else:
                # It does not exist. This is a DELTA.
                cursor.execute('''
                    INSERT INTO subdomains (domain_id, subdomain) 
                    VALUES (?, ?)
                ''', (domain_id, subdomain))
                return True

    def get_unscanned_subdomains(self) -> List[Tuple[int, str]]:
        """Retrieves subdomains that have not been deep-scanned yet."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, subdomain FROM subdomains WHERE is_scanned = 0')
            return cursor.fetchall()

    def mark_scanned(self, subdomain_id: int):
        """Marks a subdomain as scanned so we don't process it twice."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE subdomains SET is_scanned = 1 WHERE id = ?', (subdomain_id,))
            conn.commit()