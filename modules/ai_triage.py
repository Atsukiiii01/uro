import os
import logging
from typing import List, Dict, TypedDict
from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from core.database import DeltaDB

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the State to pass context through the graph
class TriageState(TypedDict):
    web_service_id: int
    url: str
    endpoints: List[str]
    secrets: List[Dict]
    analysis_report: str

class AITriageAgent:
    def __init__(self):
        # Using gemini-1.5-flash for high-speed, cost-effective reasoning
        # It automatically looks for the GOOGLE_API_KEY environment variable
        self.llm = ChatGoogleGenerativeAI(model="gemini-pro", temperature=0.2)
        self.db = DeltaDB()
        self.graph = self._build_graph()

    def _fetch_context(self, state: TriageState) -> TriageState:
        """Reads the structural data from SQLite to feed the LLM."""
        logging.info(f"Fetching context for Web Service ID: {state['web_service_id']}")
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get Endpoints
            cursor.execute('SELECT path FROM endpoints WHERE web_service_id = ?', (state['web_service_id'],))
            state['endpoints'] = [row[0] for row in cursor.fetchall()]
            
            # Get Secrets
            cursor.execute('SELECT type, secret_value FROM leaked_secrets WHERE web_service_id = ?', (state['web_service_id'],))
            state['secrets'] = [{"type": row[0], "value": row[1]} for row in cursor.fetchall()]
            
        return state

    def _analyze_surface(self, state: TriageState) -> TriageState:
        """The core reasoning engine. Analyzes paths for vulnerabilities."""
        if not state['endpoints'] and not state['secrets']:
            state['analysis_report'] = "No actionable client-side intelligence found for this endpoint."
            return state

        logging.info(f"Analyzing {len(state['endpoints'])} endpoints and {len(state['secrets'])} secrets via Gemini...")

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a world-class Bug Bounty Hunter and Application Security Architect.
Your job is to review the extracted JavaScript paths and hardcoded secrets from a target web service.
Identify the top 3 most likely vulnerabilities based strictly on the endpoint structures (e.g., IDOR on /api/user/{{id}}, SSRF on /api/fetch?url=).
Do not output generic advice. Output a brutal, precise, and actionable attack plan."""),
            ("user", """Target URL: {url}
            
Extracted Paths:
{endpoints}

Extracted Secrets/Tokens:
{secrets}

Provide your prioritized attack plan:""")
        ])

        chain = prompt | self.llm
        
        endpoints_str = "\n".join(state['endpoints'][:200]) # Gemini's window is larger, we can safely expand this to 200 paths
        secrets_str = "\n".join([f"{s['type']}: [REDACTED]" for s in state['secrets']])
        
        response = chain.invoke({
            "url": state['url'],
            "endpoints": endpoints_str,
            "secrets": secrets_str
        })
        
        state['analysis_report'] = response.content
        return state

    def _build_graph(self):
        """Constructs the LangGraph state machine."""
        workflow = StateGraph(TriageState)
        
        # Add nodes
        workflow.add_node("fetch_context", self._fetch_context)
        workflow.add_node("analyze_surface", self._analyze_surface)
        
        # Define edges (The flow of logic)
        workflow.set_entry_point("fetch_context")
        workflow.add_edge("fetch_context", "analyze_surface")
        workflow.add_edge("analyze_surface", END)
        
        return workflow.compile()

    def run(self, web_service_id: int, url: str) -> str:
        """Executes the AI workflow for a specific target."""
        initial_state = TriageState(
            web_service_id=web_service_id, 
            url=url, 
            endpoints=[], 
            secrets=[], 
            analysis_report=""
        )
        
        result = self.graph.invoke(initial_state)
        return result['analysis_report']