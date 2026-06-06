import os
import logging
from typing import List, Dict, TypedDict
import json
from langgraph.graph import StateGraph, END
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from core.database import DeltaDB
from core.tool_wrapper import GoToolWrapper

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class AgentState(TypedDict):
    web_service_id: int
    url: str
    endpoints: List[str]
    secrets: List[Dict]
    verified_vulns: List[Dict]
    raw_findings: str
    final_report: str

class SupervisorFabric:
    def __init__(self):
        self.llm = ChatOllama(model="llama3.2", temperature=0.1)
        self.db = DeltaDB()
        self.go_engine = GoToolWrapper()
        self.graph = self._build_fabric()

    def _clean_and_enrich_telemetry(self, state: AgentState) -> AgentState:
        """Ingestion Layer: Filters noise and runs active Go verification."""
        logging.info(f"[Supervisor] Fetching telemetry for Web Service ID: {state['web_service_id']}")
        
        # 1. Database Read
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT path FROM endpoints WHERE web_service_id = ?', (state['web_service_id'],))
            raw_paths = [row[0] for row in cursor.fetchall()]
            cursor.execute('SELECT type, secret_value FROM leaked_secrets WHERE web_service_id = ?', (state['web_service_id'],))
            state['secrets'] = [{"type": row[0], "value": row[1]} for row in cursor.fetchall()]

        # 2. Deterministic Filtering: Strip standard web noise and hallucinations
        blacklisted_patterns = ["/404", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".css", "favicon.ico"]
        state['endpoints'] = [
            path for path in raw_paths 
            if not any(pattern in path.lower() for pattern in blacklisted_patterns)
        ]

        # 3. Network Telemetry Enrichment via Go Httpx
        logging.info(f"[Supervisor] Fingerprinting stack via Go Engine: {state['url']}")
        tech_fingerprint = self.go_engine.run_httpx_probe(state['url'])
        detected_tech = tech_fingerprint.get("tech", [])
        if detected_tech:
            logging.info(f"[Supervisor] Active stack fingerprint completed: {detected_tech}")
            state['endpoints'].append(f"VERIFIED_INFRASTRUCTURE_STACK: {detected_tech}")

        # 4. Active Signature Scan via Go Nuclei to anchor the LLM
        logging.info(f"[Supervisor] Executing target validation signatures via Go Nuclei...")
        # Running fast, low-impact infrastructure templates
        nuclei_results = self.go_engine.run_nuclei_scan(state['url'], tags="tech,misconfig")
        
        state['verified_vulns'] = []
        for match in nuclei_results:
            state['verified_vulns'].append({
                "template_id": match.get("template-id"),
                "name": match.get("info", {}).get("name"),
                "severity": match.get("info", {}).get("severity"),
                "matched_line": match.get("matched-at")
            })
            
        logging.info(f"[Supervisor] Active validation complete. Found {len(state['verified_vulns'])} verified vulnerabilities.")
        return state

    def _triage_agent(self, state: AgentState) -> AgentState:
        """Triage Layer: Cross-references structural endpoints against verified scanner signatures."""
        logging.info("[Triage Agent] Performing cross-verification analysis...")

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are the Triage Agent in an autonomous security OS.
Your objective is to analyze potential threat surfaces. You are provided with filtered web paths, leaked secrets, and raw verified scanning signatures from an active Go network engine.

CRITICAL RULES:
1. Prioritize raw scanner matches from 'Verified Scanning Signatures' over unverified web paths.
2. Do not report standard error pages, routing mechanics, or 404 paths as vulnerabilities.
3. If no verified signatures or severe route anomalies are found, state explicitly that the surface is currently secure.
4. Output a dense, highly technical summary of legitimate threat exposures."""),
            ("user", """Target URL: {url}
Filtered App Paths: {endpoints}
Leaked Secrets: {secrets}
Verified Scanning Signatures (Empirical Proof): {verified_vulns}
Raw Findings Matrix:""")
        ])
        
        chain = prompt | self.llm
        response = chain.invoke({
            "url": state['url'],
            "endpoints": "\n".join(state['endpoints'][:100]),
            "secrets": "\n".join([f"{s['type']}: {s['value'][:60]}" for s in state['secrets']]),
            "verified_vulns": json.dumps(state['verified_vulns'], indent=2) if state['verified_vulns'] else "No active scanner signatures triggered."
        })
        state['raw_findings'] = response.content
        return state

    def _reporting_agent(self, state: AgentState) -> AgentState:
        """Documentation Layer: Drafts high-fidelity HackerOne disclosures."""
        logging.info("[Reporting Agent] Compiling professional markdown defense report...")

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a Senior Security Advisory writer. Translate the provided findings matrix into a clean, professional bug bounty disclosure report.
Use strict markdown. Do not add conversational conversational text.
Structure:
- Title
- Target
- Verified Exposure Vectors (Include details from the scanning signatures if present)
- Remediation Strategies"""),
            ("user", """Findings Matrix:
{raw_findings}

Generate the Final Markdown Portfolio:""")
        ])
        
        chain = prompt | self.llm
        response = chain.invoke({"raw_findings": state['raw_findings']})
        state['final_report'] = response.content
        return state

    def _build_fabric(self):
        workflow = StateGraph(AgentState)
        
        workflow.add_node("enrichment", self._clean_and_enrich_telemetry)
        workflow.add_node("triage", self._triage_agent)
        workflow.add_node("reporting", self._reporting_agent)
        
        workflow.set_entry_point("enrichment")
        workflow.add_edge("enrichment", "triage")
        workflow.add_edge("triage", "reporting")
        workflow.add_edge("reporting", END)
        
        return workflow.compile()

    def run(self, web_service_id: int, url: str) -> str:
        import json
        initial_state = AgentState(
            web_service_id=web_service_id, 
            url=url, 
            endpoints=[], 
            secrets=[], 
            verified_vulns=[],
            raw_findings="",
            final_report=""
        )
        result = self.graph.invoke(initial_state)
        return result['final_report']