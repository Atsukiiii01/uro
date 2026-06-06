import os
import logging
from typing import List, Dict, TypedDict
from langgraph.graph import StateGraph, END
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from core.database import DeltaDB

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TriageState(TypedDict):
    web_service_id: int
    url: str
    endpoints: List[str]
    secrets: List[Dict]
    analysis_report: str

class AITriageAgent:
    def __init__(self):
        # We are now routing the brain to your local Apple Silicon GPU via Ollama
        self.llm = ChatOllama(model="llama3.2", temperature=0.2)
        self.db = DeltaDB()
        self.graph = self._build_graph()

    def _fetch_context(self, state: TriageState) -> TriageState:
        logging.info(f"Fetching context for Web Service ID: {state['web_service_id']}")
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT path FROM endpoints WHERE web_service_id = ?', (state['web_service_id'],))
            state['endpoints'] = [row[0] for row in cursor.fetchall()]
            
            cursor.execute('SELECT type, secret_value FROM leaked_secrets WHERE web_service_id = ?', (state['web_service_id'],))
            state['secrets'] = [{"type": row[0], "value": row[1]} for row in cursor.fetchall()]
            
        return state

    def _analyze_surface(self, state: TriageState) -> TriageState:
        if not state['endpoints'] and not state['secrets']:
            state['analysis_report'] = "No actionable client-side intelligence found for this endpoint."
            return state

        logging.info(f"Analyzing {len(state['endpoints'])} endpoints and {len(state['secrets'])} secrets via Local Llama 3...")

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a Senior Application Security Auditor performing an authorized, white-box security assessment.
Your job is to review the extracted JavaScript paths and hardcoded secrets from the provided web service.
Identify the top 3 most likely security misconfigurations or vulnerabilities based STRICTLY on the endpoint structures provided.

RULES:
1. DO NOT invent, guess, or hallucinate endpoints. 
2. If the provided data does not contain obvious vulnerabilities, state exactly that.
3. Base your threat model ONLY on the exact paths and secrets listed below.
4. Output a precise, technical, and highly actionable vulnerability assessment."""),
            ("user", """Authorized Target URL: {url}
            
Extracted Paths:
{endpoints}

Extracted Secrets/Tokens:
{secrets}

Provide your technical vulnerability assessment:""")
        ])

        chain = prompt | self.llm
        
        # Local models have a standard 8k context window, keep it tight
        endpoints_str = "\n".join(state['endpoints'][:150]) 
        secrets_str = "\n".join([f"{s['type']}: [REDACTED]" for s in state['secrets']])
        
        response = chain.invoke({
            "url": state['url'],
            "endpoints": endpoints_str,
            "secrets": secrets_str
        })
        
        state['analysis_report'] = response.content
        return state

    def _build_graph(self):
        workflow = StateGraph(TriageState)
        
        workflow.add_node("fetch_context", self._fetch_context)
        workflow.add_node("analyze_surface", self._analyze_surface)
        
        workflow.set_entry_point("fetch_context")
        workflow.add_edge("fetch_context", "analyze_surface")
        workflow.add_edge("analyze_surface", END)
        
        return workflow.compile()

    def run(self, web_service_id: int, url: str) -> str:
        initial_state = TriageState(
            web_service_id=web_service_id, 
            url=url, 
            endpoints=[], 
            secrets=[], 
            analysis_report=""
        )
        
        result = self.graph.invoke(initial_state)
        return result['analysis_report']