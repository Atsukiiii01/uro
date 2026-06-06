from modules.ai_triage import AITriageAgent
from core.database import DeltaDB

def main():
    db = DeltaDB()
    
    # Extract the first verified web service that actually has harvested endpoints
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT w.id, w.url 
            FROM web_services w
            JOIN endpoints e ON w.id = e.web_service_id
            LIMIT 1
        ''')
        target = cursor.fetchone()

    if not target:
        print("[-] No web services with extracted endpoints found in the database.")
        print("[*] Triage requires data. Run: python main.py hackerone.com first.")
        return

    target_id, target_url = target
    print(f"[*] Launching Gemini AI Triage against: {target_url} (ID: {target_id})")
    
    # Execute the LangGraph State Machine
    agent = AITriageAgent()
    report = agent.run(web_service_id=target_id, url=target_url)
    
    print("\n" + "="*50)
    print("🧠 GEMINI AI ATTACK PLAN")
    print("="*50)
    print(report)

if __name__ == "__main__":
    main()