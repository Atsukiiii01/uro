import argparse
import logging
import sys
import os
import re
from core.database import DeltaDB
from core.config import ConfigManager
from modules.ai_triage import TriageAgent
from modules.recon import ReconEngine
from modules.prober import LiveProber
from modules.js_analyzer import JSAnalyzer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def initialize_profile(profile_path: str):
    cfg = ConfigManager()
    cfg.load_profile(profile_path)

def cmd_scan(args):
    initialize_profile(args.profile)
    target_domain = args.target
    
    db = DeltaDB()
    domain_id = db.add_domain(target_domain)
    
    print(f"\n[*] Target: {target_domain} (ID: {domain_id})")
    print("[*] Phase 1: Gathering passive intelligence...")

    engine = ReconEngine(target_domain)
    discovered_assets = engine.run_all()
    
    # Explicitly append the direct target to make sure standalone hosts scan
    discovered_assets.add(target_domain)

    new_assets_to_probe = {}

    print("\n[*] Phase 2: Evaluating Deltas...")
    with db._get_connection() as conn:
        cursor = conn.cursor()
        for sub in discovered_assets:
            cursor.execute('SELECT id FROM subdomains WHERE subdomain = ?', (sub,))
            result = cursor.fetchone()
            
            if not result:
                cursor.execute('INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)', (domain_id, sub))
                new_id = cursor.lastrowid
                new_assets_to_probe[new_id] = sub
                print(f"[+] NEW DELTA: {sub}")
            else:
                cursor.execute('UPDATE subdomains SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (result[0],))

    print(f"\n[+] Found {len(new_assets_to_probe)} assets targeting execution queue.")

    if new_assets_to_probe:
        print("\n[*] Phase 3: Launching Live Prober on Targets...")
        prober = LiveProber(threads=10)
        live_services = prober.run(new_assets_to_probe)

        print("\n[*] Phase 4: Committing verified web services & extracting JS Intel...")
        for service in live_services:
            db.add_web_service(
                subdomain_id=service["subdomain_id"],
                url=service["url"],
                status_code=service["status_code"],
                content_length=service["content_length"],
                title=service["title"]
            )
            
            with db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT id FROM web_services WHERE url = ?', (service["url"],))
                row = cursor.fetchone()

            if row is None:
                logging.error(f"[!] Could not retrieve service ID for {service['url']} — skipping JS analysis")
                continue
                
            service_id = row[0]

            print(f"    └── Parsing scripts on {service['url']}...")
            analyzer = JSAnalyzer(service["url"])
            intel = analyzer.analyze()

            if intel["paths"]:
                for path in intel["paths"]:
                    db.add_endpoint(web_service_id=service_id, path=path, source="js_analyzer")

            if intel["secrets"]:
                print(f"        [!] CRITICAL: Found {len(intel['secrets'])} potential hardcoded credentials!")
                for secret in intel["secrets"]:
                    db.add_secret(web_service_id=service_id, secret_type=secret["type"], value=secret["value"], location=secret["location"])

            db.mark_scanned(service["subdomain_id"])
        
        print(f"\n[+] Processing complete. Attack surface data fully structured inside data/uro.db")
    else:
        print("\n[*] No new assets require probing or static code analysis.")

def cmd_triage(args):
    initialize_profile(args.profile)
    target = args.target
    cfg = ConfigManager()
    
    scope_rules = ""
    if cfg.scope_file:
        try:
            with open(cfg.scope_file, "r", encoding="utf-8") as f:
                scope_rules = f.read()
            logging.info(f"[*] Loaded AI scope constraints from: {cfg.scope_file}")
        except Exception as e:
            logging.error(f"[-] Failed to read AI scope file: {e}")

    logging.info(f"[*] Initializing Triage Engine for target: {target}")
    
    db = DeltaDB()
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, url FROM web_services WHERE url LIKE ?', (f"%{target}%",))
        result = cursor.fetchone()
        
    if not result:
        logging.error(f"[-] Target {target} not found in database. Run 'scan' first.")
        return

    ws_id, exact_url = result[0], result[1]
    logging.info(f"[*] Launching Local AI Triage against: {exact_url} (ID: {ws_id})")
    
    agent = TriageAgent()
    report = agent.run(web_service_id=ws_id, url=exact_url, scope_rules=scope_rules)
    
    print("\n============================================================")
    print(" VULNERABILITY ASSESSMENT & ATTACK PATHS")
    print("============================================================")
    print(report)

def cmd_hunt(args):
    initialize_profile(args.profile)
    cfg = ConfigManager()
    
    scope_rules = ""
    if cfg.scope_file:
        try:
            with open(cfg.scope_file, "r", encoding="utf-8") as f:
                scope_rules = f.read()
        except Exception:
            pass

    db = DeltaDB()
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT DISTINCT w.id, w.url 
            FROM web_services w
            LEFT JOIN endpoints e ON w.id = e.web_service_id
            LEFT JOIN leaked_secrets s ON w.id = s.web_service_id
            WHERE w.status_code IN (200, 401, 403) 
            AND (e.id IS NOT NULL OR s.id IS NOT NULL)
        ''')
        viable_targets = cursor.fetchall()

    if not viable_targets:
        logging.info("[*] No high-value targets with extracted intel found in the database. Scan more assets.")
        return

    logging.info(f"[*] Batch Orchestrator engaged. Queuing {len(viable_targets)} high-value targets for AI Triage.")
    agent = TriageAgent()

    for ws_id, exact_url in viable_targets:
        print(f"\n============================================================")
        print(f" TARGET: {exact_url}")
        print(f"============================================================")
        try:
            report = agent.run(web_service_id=ws_id, url=exact_url, scope_rules=scope_rules)
            print(report)
        except Exception as e:
            logging.error(f"[-] Triage Agent crashed on {exact_url}: {e}")
            continue

def main():
    if os.getenv("LANGCHAIN_TRACING_V2") == "true":
        logging.warning("[!] LangSmith tracing is ENABLED. Recon data will be uploaded to smith.langchain.com.")

    parser = argparse.ArgumentParser(description="Autonomous Offensive Security OS")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run discovery and JS intelligence extraction")
    scan_parser.add_argument("target", help="Root domain or direct host to scan")
    scan_parser.add_argument("--profile", "-p", help="Path to YAML operational profile", required=True)
    scan_parser.set_defaults(func=cmd_scan)

    triage_parser = subparsers.add_parser("triage", help="Run local AI triage on a specific target")
    triage_parser.add_argument("target", help="Target URL or fuzzy string to triage")
    triage_parser.add_argument("--profile", "-p", help="Path to YAML operational profile", required=True)
    triage_parser.set_defaults(func=cmd_triage)

    hunt_parser = subparsers.add_parser("hunt", help="Batch triage all viable, data-rich targets in the database")
    hunt_parser.add_argument("--profile", "-p", help="Path to YAML operational profile", required=True)
    hunt_parser.set_defaults(func=cmd_hunt)

    args = parser.parse_args()

    # A-7: Enforce domain validation before allowing the scan to execute
    if args.command == "scan":
        domain_re = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
        if not domain_re.match(args.target):
            logging.error(f"[-] Invalid domain format: {args.target}")
            sys.exit(1)

    # A-6: Global SIGINT handler
    try:
        args.func(args)
    except KeyboardInterrupt:
        logging.warning("\n[!] SIGINT received. Gracefully shutting down and preserving database state...")
        sys.exit(0)

if __name__ == "__main__":
    main()