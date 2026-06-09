import logging
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from core.database import DeltaDB

class TriageAgent:
    def __init__(self):
        # Temperature 0.0 is mandatory, but not sufficient on its own.
        self.llm = OllamaLLM(
            model="llama3.2:latest",
            temperature=0.0
        )

    def _fetch_telemetry(self, web_service_id: int) -> dict:
        """Queries the database to extract raw endpoints and secrets for the target."""
        db = DeltaDB()
        telemetry = {"endpoints": [], "secrets": []}
        
        with db._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT path, source FROM endpoints WHERE web_service_id = ?", 
                (web_service_id,)
            )
            telemetry["endpoints"] = [f"{row[0]} (Source: {row[1]})" for row in cursor.fetchall()]
            
            cursor.execute(
                "SELECT type, secret_value FROM leaked_secrets WHERE web_service_id = ?", 
                (web_service_id,)
            )
            for secret_type, value in cursor.fetchall():
                # Strict programmatic False-Positive Filtering
                val_lower = value.lower()
                if secret_type == "HIGH_ENTROPY_TOKEN":
                    if any(x in val_lower for x in ["client_id", "utm_", "pk_", "public"]):
                        continue
                if len(value) == 20 and value.isalnum() and value.islower():
                    continue
                    
                telemetry["secrets"].append({"type": secret_type, "value": value})
                
        return telemetry

    def run(self, web_service_id: int, url: str, scope_rules: str) -> str:
        """Executes deterministic triage on actual database telemetry records."""
        telemetry = self._fetch_telemetry(web_service_id)
        
        # Immediate short-circuit: Do not even invoke the LLM if there is no data.
        # This completely eliminates the LLM's opportunity to hallucinate data out of boredom.
        if not telemetry["endpoints"] and not telemetry["secrets"]:
            return "Surface is secure. No actionable bug bounty intelligence found."

        endpoints_str = "\n".join(telemetry['endpoints']) if telemetry['endpoints'] else "None"
        secrets_str = "\n".join([f"- [{s['type']}] {s['value']}" for s in telemetry['secrets']]) if telemetry['secrets'] else "None"

        # The Prompt Straightjacket
        # No conversational pleasantries. Just raw data and strict structural commands.
        template = """You are a headless, automated security parser.
Do not converse. Do not explain your reasoning. Do not reference your rules.
Evaluate the provided telemetry.

<TELEMETRY_DATA>
TARGET URL: {url}

EXTRACTED_ENDPOINTS:
{endpoints}

EXTRACTED_SECRETS:
{secrets}
</TELEMETRY_DATA>

TASK:
Analyze ONLY the data inside the <TELEMETRY_DATA> block. 
1. If EXTRACTED_SECRETS contains items, list them as "High-Priority Information Disclosure Candidates".
2. If EXTRACTED_ENDPOINTS reveals sensitive administrative paths (e.g., /admin, /api/v1/internal), list them as "High-Value Attack Surfaces".
3. If neither of the above is true, output EXACTLY AND ONLY the string: "Surface is secure. No actionable bug bounty intelligence found."

FORMAT: Output must be concise bullet points. No introductory text. No conversational filler.
"""
        
        prompt = PromptTemplate.from_template(template)
        chain = prompt | self.llm
        
        try:
            return chain.invoke({
                "url": url,
                "endpoints": endpoints_str,
                "secrets": secrets_str
            })
        except Exception as e:
            logging.error(f"[-] AI Triage Agent crashed processing ID {web_service_id}: {e}")
            return "Error: AI Triage Agent failed to process telemetry."