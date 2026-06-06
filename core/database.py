import sqlite3
import logging
from datetime import datetime
from typing import List, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DeltaDB:
    def __init__(self, db_path: str = "data/uro.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Creates the minimalist tables required for Delta tracking."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Track root domains (e.g., example.com)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Track subdomains (e.g., api.dev.example.com)
            # The UNIQUE constraint on subdomain allows us to catch Deltas easily.
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
            conn.commit()
            logging.info("Database initialized.")

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