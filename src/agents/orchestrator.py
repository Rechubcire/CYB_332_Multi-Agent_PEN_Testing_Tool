"""
This is the main Orchestrator agent. This agent
will lead all other agents in their tasks and
will be the "conductor" of everything
"""

from langgraph.graph import StateGraph, END
import json
from src.core.state import AgentState, log_event, log_error
from src.core.scope_guard import enforce_scope, ScopeViolationError
# from src.agents.recon import recon_agent
# from src.agents.vuln import vuln_agent
# from src.agents.report import report_agent

def build_graph():
    """
    Build the LangGraph graph with all four agents.
    This graph will be ready to invoke with the agent state
    """

    graph = StateGraph(AgentState)

    # Create the different agent nodes
    graph.add_node('orchestrator', orchestrator_agent)
    graph.add_node('recon', recon_agent)
    graph.add_node('vuln_analyst', vuln_agent)
    graph.add_node('report_writer', report_agent)

    # Set pipeline order
    graph.set_entry_point('orchestrator')
    graph.add_edge('orchestrator', 'recon')
    graph.add_edge('recon', 'vuln_analyst')
    graph.add_edge('vuln_analyst', 'report_writer')
    graph.add_edge('report_writer', END)

    return graph.compile()

def orchestrator_agent(state: AgentState) -> dict:
    """
    Creates the Orchestrator agent node, which validates
    scope and dispatches all other agents
    """

    # Try to make a connection to the LLM log what happens
    try:
        enforce_scope(state['target_ip'], state['scope'])
    except ScopeViolationError as e:
        # Log Error
        error_update = log_error(state, 'orchestrator', str(e))
        return { **error_update, 'status': "Failed"}
    
    # Log Event
    log_update = log_event(state, 'orchestrator', 
    f"Target IP of ({state['target_ip']}) in scope of ({state['scope']}). Starting agent pipeline")
    
    return { **log_update, 'status': "Running"}

def call_llm_with_retry(system_prompt: str, user_content: str, agent_name: str, max_attempts=3) -> str:
    """
    This uses call_llm() with retry logic. Adds a message
    to the end of the prompt if the llm returns invalid
    JSON. This will run until it uses all of its attempts
    """

    