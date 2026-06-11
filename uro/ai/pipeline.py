import json
import logging
from typing import List, Dict, TypedDict

from pydantic import BaseModel, Field
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END

from uro.storage.repository import DeltaDB
from uro.core.config import ConfigManager

# ==========================================
# 1. State & Schema Definitions
# ==========================================

class TriageState(TypedDict):
    web_service_id: int
    url: str
    scope_rules: str
    raw_endpoints: List[str]
    secrets: List[Dict[str, str]]
    filtered_endpoints: List[str]
    report: str

class FilteredEndpoints(BaseModel):
    high_value_routes: List[str] = Field(
        description="List of critical API, admin, or auth endpoints. Exclude all static files."
    )

class AttackPlan(BaseModel):
    vulnerability_hypothesis: str = Field(
        description="What is the most likely attack path based on the exposed routes and secrets?"
    )
    steps_to_validate: List[str] = Field(
        description="Step-by-step instructions for a human operator to verify the vulnerability."
    )
    scope_compliance: str = Field(
        description="Why this finding is strictly within the provided scope rules."
    )

# ==========================================
# 2. The Agent Fabric
# ==========================================

class TriageAgent:
    def __init__(self):
        self.cfg = ConfigManager()
        self.db = DeltaDB(self.cfg.db_path)
        
        # Enforce strict JSON formatting at the model level to prevent 3B model hallucinations
        self.llm = ChatOllama(
            model=self.cfg.ai_model,
            base_url=self.cfg.ollama_url,
            temperature=0.1,
            format="json" 
        )
        
        self.workflow = self._compile_graph()

    def _compile_graph(self) -> StateGraph:
        workflow = StateGraph(TriageState)
        
        workflow.add_node("gather_intel", self.node_gather_intel)
        workflow.add_node("filter_noise", self.node_filter_noise)
        workflow.add_node("generate_plan", self.node_generate_plan)

        workflow.set_entry_point("gather_intel")
        workflow.add_edge("gather_intel", "filter_noise")
        workflow.add_edge("filter_noise", "generate_plan")
        workflow.add_edge("generate_plan", END)

        return workflow.compile()

    def node_gather_intel(self, state: TriageState) -> TriageState:
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT path FROM endpoints WHERE web_service_id = ?', (state["web_service_id"],))
            endpoints = [row[0] for row in cursor.fetchall()]

            cursor.execute('SELECT type, secret_value FROM leaked_secrets WHERE web_service_id = ?', (state["web_service_id"],))
            secrets = [{"type": row[0], "value": row[1]} for row in cursor.fetchall()]

        return {"raw_endpoints": endpoints, "secrets": secrets}

    def node_filter_noise(self, state: TriageState) -> TriageState:
        endpoints = state.get("raw_endpoints", [])
        if not endpoints:
             return {"filtered_endpoints": []}

        # Hard cap inputs to protect the 3B model's context window
        endpoints_str = "\n".join(endpoints[:150]) 
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are an expert security analyst. Filter the provided list of URL paths. Extract ONLY high-value targets: API endpoints, admin panels, authentication routes, and sensitive data exposure paths. Discard ALL static assets, marketing pages, and irrelevant noise."),
            ("human", "Paths:\n{paths}")
        ])

        structured_llm = self.llm.with_structured_output(FilteredEndpoints)
        chain = prompt | structured_llm
        
        try:
            result = chain.invoke({"paths": endpoints_str})
            return {"filtered_endpoints": result.high_value_routes}
        except Exception as e:
            logging.warning(f"[!] LLM filtering failed, falling back to heuristic slice: {e}")
            return {"filtered_endpoints": endpoints[:10]}

    def node_generate_plan(self, state: TriageState) -> TriageState:
        filtered = state.get("filtered_endpoints", [])
        secrets = state.get("secrets", [])
        
        if not filtered and not secrets:
            return {"report": "No actionable intelligence or high-value routes found. Target deprioritized."}

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an offensive security AI operating under strict rules of engagement.
Scope constraints:
{scope}

Analyze the target: {url}

High-Value Routes:
{routes}

Leaked Secrets:
{secrets}

Generate a concise, actionable attack plan focusing ONLY on high-impact vulnerabilities (Account Takeover, Auth Bypass, Data Exposure). You must verify that your plan complies with the Scope constraints."""),
            ("human", "Generate the attack plan now.")
        ])

        structured_llm = self.llm.with_structured_output(AttackPlan)
        chain = prompt | structured_llm

        try:
            result = chain.invoke({
                "scope": state.get("scope_rules") or "No specific scope provided. Assume standard bug bounty rules.",
                "url": state["url"],
                "routes": "\n".join(filtered) if filtered else "None",
                "secrets": json.dumps(secrets) if secrets else "None"
            })
            
            report = (
                f"=== AI Triage Report: {state['url']} ===\n"
                f"[!] Hypothesis: {result.vulnerability_hypothesis}\n\n"
                f"[*] Validation Steps:\n"
            )
            for i, step in enumerate(result.steps_to_validate, 1):
                report += f"    {i}. {step}\n"
            report += f"\n[+] Scope Check: {result.scope_compliance}\n"
            
            return {"report": report}

        except Exception as e:
            logging.error(f"[-] LLM triage generation failed: {e}")
            return {"report": "AI Triage failed to generate a valid attack plan due to model output constraints."}

    def run(self, web_service_id: int, url: str, scope_rules: str) -> str:
        initial_state = {
            "web_service_id": web_service_id,
            "url": url,
            "scope_rules": scope_rules,
            "raw_endpoints": [],
            "secrets": [],
            "filtered_endpoints": [],
            "report": ""
        }
        
        try:
            final_state = self.workflow.invoke(initial_state)
            return final_state.get("report", "No report generated.")
        except Exception as e:
            logging.error(f"[-] Graph execution crashed on {url}: {e}")
            return "Execution pipeline failed."