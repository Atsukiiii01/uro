import sys
from core.database import DeltaDB
from modules.recon import ReconEngine

def main():
    # Let's target a bug bounty asset with an open policy or a test domain.
    # To keep this safe and focused, pass the domain via argument or use a default.
    target_domain = sys.argv[1] if len(sys.argv) > 1 else "testfire.net"
    
    db = DeltaDB()
    domain_id = db.add_domain(target_domain)
    
    print(f"\n[*] Target Target: {target_domain} (ID: {domain_id})")
    print("[*] Initiating passive intelligence collection...")

    # Initialize the engine
    engine = ReconEngine(target_domain)
    discovered_assets = engine.run_all()

    print("\n[*] Parsing results for Delta Triggers...")
    delta_count = 0
    
    for sub in discovered_assets:
        is_new = db.process_subdomain(domain_id, sub)
        if is_new:
            print(f"[+] DELTA: {sub}")
            delta_count += 1

    print(f"\n[+] Processing complete. Discovered {delta_count} brand-new assets.")

if __name__ == "__main__":
    main()