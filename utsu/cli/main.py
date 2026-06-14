import argparse
import logging
import sys
import os
import time
from utsu.storage.repository import DeltaDB
from utsu.core.config import ConfigManager
from utsu.ai.pipeline import TriageAgent
from utsu.plugins.subdomain.recon import ReconEngine
from utsu.probing.client import LiveProber
from utsu.plugins.js_analysis.analyzer import JSAnalyzer
from utsu.core.reporting import ReportManager

try:
    from utsu import utsu_rust_core # type: ignore
    RUST_CORE_ACTIVE = True
except ImportError:
    RUST_CORE_ACTIVE = False
    logging.warning("[!] uro_rust_core binary mapping missing in current environment setup.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def initialize_profile(profile_path: str):
    cfg = ConfigManager()
    cfg.load_profile(profile_path)

def cmd_scan(args):
    initialize_profile(args.profile)
    cfg = ConfigManager()
    target_domain = args.target

    if args.force:
        logging.info(f"[*] --force flag detected. Wiping operational database at {cfg.db_path}...")
        if os.path.exists(cfg.db_path):
            os.remove(cfg.db_path)
            
    db = DeltaDB(cfg.db_path)
    domain_id = db.add_domain(target_domain)
    
    print(f"\n[*] Target: {target_domain} (ID: {domain_id})")
    print("[*] Phase 1: Gathering passive intelligence...")

    engine = ReconEngine(target_domain)
    discovered_assets = engine.run_all()
    discovered_assets.add(target_domain)

    print("\n[*] Phase 2: Evaluating Deltas (Bulk Processing)...")
    new_assets_to_probe = {}

    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, subdomain FROM subdomains WHERE domain_id = ?', (domain_id,))
        existing_assets = {row[1]: row[0] for row in cursor.fetchall()}
        
        new_subs = discovered_assets - existing_assets.keys()
        subs_to_update = discovered_assets.intersection(existing_assets.keys())

        if new_subs:
            cursor.executemany(
                'INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)', 
                [(domain_id, sub) for sub in new_subs]
            )
            cursor.execute('SELECT id, subdomain FROM subdomains WHERE domain_id = ?', (domain_id,))
            updated_assets = {row[1]: row[0] for row in cursor.fetchall()}
            
            for sub in new_subs:
                new_assets_to_probe[updated_assets[sub]] = sub
                print(f"[+] NEW DELTA: {sub}")

        if subs_to_update:
            cursor.executemany(
                'UPDATE subdomains SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', 
                [(existing_assets[sub],) for sub in subs_to_update]
            )

    print(f"\n[+] Found {len(new_assets_to_probe)} assets targeting execution queue.")

    if new_assets_to_probe:
        print("\n[*] Phase 3: Launching Live Prober on Targets...")
        prober = LiveProber(threads=cfg.prober_threads, rps=cfg.rate_limit_rps, custom_headers=cfg.custom_headers)
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
            
            service_id = db.get_web_service_id_by_url(service["url"])
            if not service_id:
                logging.error(f"[!] Could not retrieve service ID for {service['url']} — skipping JS analysis")
                continue
                
            print(f"    └── Parsing scripts on {service['url']}...")
            
            analyzer = JSAnalyzer(service["url"], custom_headers=cfg.custom_headers)
            intel = analyzer.analyze()

            if intel["paths"]:
                for path in intel["paths"]:
                    db.add_endpoint(web_service_id=service_id, path=path, source="js_analyzer")

            if intel["secrets"]:
                print(f"        [!] CRITICAL: Found {len(intel['secrets'])} potential hardcoded credentials!")
                for secret in intel["secrets"]:
                    db.add_secret(web_service_id=service_id, secret_type=secret["type"], value=secret["value"], location=secret["location"])

            db.mark_scanned(service["subdomain_id"])
        print(f"\n[+] Processing complete. Attack surface data fully structured inside {cfg.db_path}")
    else:
        print("\n[*] No new assets require probing or static code analysis.")

def cmd_triage(args):
    initialize_profile(args.profile)
    cfg = ConfigManager()
    target = args.target
    scope_rules = ""
    if cfg.scope_file:
        try:
            with open(cfg.scope_file, "r", encoding="utf-8") as f:
                scope_rules = f.read()
        except Exception:
            pass

    db = DeltaDB(cfg.db_path)
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, url FROM web_services WHERE url LIKE ?', (f"%{target}%",))
        result = cursor.fetchone()
        if not result:
            logging.error(f"[-] Target '{target}' not found in database.")
            return

    ws_id, exact_url = result[0], result[1]
    
    print(f"\n[*] Initiating AI Triage for target: {exact_url}...")
    agent = TriageAgent()
    reporter = ReportManager()
    
    try:
        report = agent.run(web_service_id=ws_id, url=exact_url, scope_rules=scope_rules)
        if report:
            print(f"\n{report}")
            reporter.save_triage_report(exact_url, report)
    except Exception as e:
        print(f"[-] Triage execution failed: {e}")

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

    db = DeltaDB(cfg.db_path)
    reporter = ReportManager()
    
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
        print("[-] No viable targets with extracted intelligence found for hunting.")
        return

    print(f"\n[*] Hunt Execution Started. {len(viable_targets)} viable targets in AI queue.")
    agent = TriageAgent()
    
    for index, (ws_id, exact_url) in enumerate(viable_targets, 1):
        print(f"\n[{index}/{len(viable_targets)}] Processing {exact_url} through LangGraph pipeline...")
        try:
            report = agent.run(web_service_id=ws_id, url=exact_url, scope_rules=scope_rules)
            if report:
                print(f"{report}")
                reporter.save_triage_report(exact_url, report)
            
            # API Pacing to respect cloud infrastructure limits
            time.sleep(2.5)
            
        except RuntimeError as e:
            if "GROQ_RATE_LIMIT" in str(e):
                print(f"\n[!] CRITICAL: API Rate Limit exhausted. Halting execution to preserve target queue.")
                break
            print(f"    └── [!] Triage failed on {exact_url}: {e}")
        except Exception as e:
            print(f"    └── [!] Triage failed on {exact_url}: {e}")
            continue

def main():
    parser = argparse.ArgumentParser(description="Autonomous Offensive Security OS")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--profile", "-p", required=True)
    scan_parser.add_argument("--force", action="store_true", help="Wipe database and force a fresh scan")
    scan_parser.set_defaults(func=cmd_scan)

    triage_parser = subparsers.add_parser("triage")
    triage_parser.add_argument("target")
    triage_parser.add_argument("--profile", "-p", required=True)
    triage_parser.set_defaults(func=cmd_triage)

    hunt_parser = subparsers.add_parser("hunt")
    hunt_parser.add_argument("--profile", "-p", required=True)
    hunt_parser.set_defaults(func=cmd_hunt)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user. Exiting cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    main()