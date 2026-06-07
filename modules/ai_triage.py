import logging
from typing import TypedDict, List, Dict
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# Adjust these imports if your project structure differs slightly
from core.tool_wrapper import GoWrapper 
from core.database import DeltaDB

class AgentState(TypedDict):
    web_service_id: int
    url: str
    scope_rules: str
    stack: List[str]
    nuclei_vulns: List[Dict]
    paths: List[str]
    secrets: List[Dict]
    report: str

class SupervisorFabric:
    def __init__(self):
        # Ensure you have your local LLM running (e.g., Llama3 via Ollama)'
        self.llm = OllamaLLM(model="llama3.2:latest") 
        self.go_engine = GoWrapper()
        
    def _gather_telemetry(self, state: AgentState) -> AgentState:
        logging.info(f"[Supervisor] Fetching telemetry for Web Service ID: {state['web_service_id']}")
        db = DeltaDB()
        with db._get_connection() as conn:
            cursor = conn.cursor()
            
            # Fetch extracted routes
            cursor.execute("SELECT path FROM endpoints WHERE web_service_id = ?", (state["web_service_id"],))
            state["paths"] = [row[0] for row in cursor.fetchall()]
            
            # Fetch extracted high-entropy secrets - FIXED
            cursor.execute("SELECT type, secret_value FROM leaked_secrets WHERE web_service_id = ?", (state["web_service_id"],))
            state["secrets"] = [{"type": row[0], "value": row[1]} for row in cursor.fetchall()]
            
        return state

    def _active_fingerprint(self, state: AgentState) -> AgentState:
        logging.info(f"[Supervisor] Fingerprinting stack via Go Engine: {state['url']}")
        state["stack"] = self.go_engine.run_httpx(state["url"])
        logging.info(f"[Supervisor] Active stack fingerprint completed: {state['stack']}")
        return state

    def _active_validation(self, state: AgentState) -> AgentState:
        logging.info("[Supervisor] Executing target validation signatures via Go Nuclei...")
        state["nuclei_vulns"] = self.go_engine.run_nuclei(state["url"])
        logging.info(f"[Supervisor] Active validation complete. Found {len(state['nuclei_vulns'])} verified vulnerabilities.")
        return state

    def _triage_agent(self, state: AgentState) -> AgentState:
        logging.info("[Triage Agent] Performing cross-verification analysis against program scope...")
        
        scope_directive = ""
        if state.get("scope_rules"):
            scope_directive = f"""
CRITICAL SCOPE DIRECTIVE:
You must strictly evaluate all findings against the following Bug Bounty Program Rules:
<program_rules>
{state["scope_rules"]}
</program_rules>

RUTHLESSLY FILTER OUT ANY FINDING THAT MATCHES THE 'OUT OF SCOPE' OR 'EXCLUSIONS' LIST ABOVE.
Do not mention out-of-scope items in your report. If the telemetry contains ONLY out-of-scope items, your entire report must be exactly: "Surface is secure. No actionable bug bounty intelligence found."
"""
        else:
            scope_directive = "No specific scope rules provided. Use general offensive security triage best practices, but ignore low-impact informational noise (e.g., missing HTTP headers)."

        system_prompt = f"""You are an elite offensive security triage engineer evaluating telemetry.
{scope_directive}

If a high-entropy secret (e.g., API Key, JWT) is found, highlight it but demand manual verification of impact. 
Do not write generic corporate recommendations. Focus purely on exploitability, impact, and adherence to the program rules."""

        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            ("human", "Target: {url}\nStack: {stack}\nSignatures: {nuclei}\nRoutes: {paths}\nSecrets: {secrets}")
        ])
        
        chain = prompt | self.llm | StrOutputParser()
        
        # Defensively truncate secrets to 60 characters to prevent context window explosion
        response = chain.invoke({
            "url": state["url"],
            "stack": state["stack"],
            "nuclei": "\n".join([str(v) for v in state["nuclei_vulns"]]),
            "paths": "\n".join(state["paths"][:50]),
            "secrets": "\n".join([f"{s['type']}: {s['value'][:60]}" for s in state["secrets"]])
        })
        
        state["report"] = response
        return state

    def run(self, web_service_id: int, url: str, scope_rules: str = "") -> str:
        """Executes the multi-agent graph sequentially."""
        initial_state: AgentState = {
            "web_service_id": web_service_id,
            "url": url,
            "scope_rules": scope_rules,
            "stack": [],
            "nuclei_vulns": [],
            "paths": [],
            "secrets": [],
            "report": ""
        }
        
        state = self._gather_telemetry(initial_state)
        state = self._active_fingerprint(state)
        state = self._active_validation(state)
        final_state = self._triage_agent(state)
        
        return final_state["report"]