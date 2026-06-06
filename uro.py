import argparse
import sys
import logging
from core.database import DeltaDB
from modules.recon import ReconEngine
from modules.prober import LiveProber
from modules.js_analyzer import JSAnalyzer
from modules.ai_triage import AITriageAgent

# Silence massive debug logs from third-party libraries
logging.getLogger("httpx").setLevel(logging.WARNING)

def cmd_scan(args):
    """Executes the Recon -> Delta -> Prober -> JS Extraction pipeline."""
    target_domain = args.domain
    db = DeltaDB()
    domain_id = db.add_domain(target_domain)
    
    print(f"\n[*] Target: {target_domain} (ID: {domain_id})")
    print("[*] Phase 1: Gathering passive intelligence...")

    engine = ReconEngine(target_domain)
    discovered_assets = engine.run_all()

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

    print(f"\n[+] Found {len(new_assets_to_probe)} brand-new assets.")

    if new_assets_to_probe:
        print("\n[*] Phase 3: Launching Live Prober on Delta Assets...")
        prober = LiveProber(threads=20)
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
                service_id = cursor.fetchone()[0]

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
    """Executes the Local AI Reasoning engine on extracted data."""
    db = DeltaDB()
    target_url = args.url
    
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM web_services WHERE url = ?', (target_url,))
        result = cursor.fetchone()
        
    if not result:
        print(f"[-] Target {target_url} not found in database. Run 'scan' first.")
        sys.exit(1)
        
    target_id = result[0]
    print(f"\n[*] Launching Local AI Triage against: {target_url} (ID: {target_id})")
    
    agent = AITriageAgent()
    report = agent.run(web_service_id=target_id, url=target_url)
    
    print("\n" + "="*60)
    print(" VULNERABILITY ASSESSMENT & ATTACK PATHS")
    print("="*60)
    print(report)


def main():
    parser = argparse.ArgumentParser(description="Uro: Autonomous Bug Bounty Operating System")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan Command
    scan_parser = subparsers.add_parser("scan", help="Run the continuous recon and delta extraction pipeline")
    scan_parser.add_argument("domain", help="Target root domain (e.g., tesla.com)")

    # Triage Command
    triage_parser = subparsers.add_parser("triage", help="Run local AI reasoning over a specific extracted web service")
    triage_parser.add_argument("url", help="Target URL stored in the DB (e.g., https://api.tesla.com/)")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "triage":
        cmd_triage(args)

if __name__ == "__main__":
    main()