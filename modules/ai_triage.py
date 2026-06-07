import logging
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate

class TriageAgent:
    def __init__(self):
        # Initializing the local Llama inference model
        self.llm = OllamaLLM(model="llama3.2:latest")

    def run(self, web_service_id: int, url: str, scope_rules: str) -> str:
        """
        Executes a scoped triage analysis on the provided web service telemetry.
        """
        scope_directive = f"SCOPE RULES:\n{scope_rules}" if scope_rules else "SCOPE RULES: None provided."
        
        system_prompt = f"""You are an elite offensive security triage engineer. Your ONLY job is to filter noise.
{scope_directive}

STRICT OPERATING RULES:
1. DO NOT invent, assume, or guess vulnerabilities.
2. If the 'Signatures' (Nuclei) section is empty or timed out, YOU MUST NOT report any active vulnerabilities like XSS, SQLi, or IDOR. Paths are just URLs, not vulnerabilities.
3. If a high-entropy secret is found in the 'Secrets' list, report it strictly as an 'Information Disclosure candidate requiring manual review'. 
4. If no Nuclei signatures fired and no hardcoded secrets exist, your output MUST BE EXACTLY: "Surface is secure. No actionable bug bounty intelligence found."
"""

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("user", f"Analyze telemetry for {url}. Identify if any critical vulnerability exists based on verified signatures or high-entropy secrets.")
        ])

        chain = prompt | self.llm
        try:
            response = chain.invoke({"url": url})
            return response
        except Exception as e:
            logging.error(f"[-] AI Triage Agent crashed: {e}")
            return "Error: AI Triage Agent failed to process telemetry."