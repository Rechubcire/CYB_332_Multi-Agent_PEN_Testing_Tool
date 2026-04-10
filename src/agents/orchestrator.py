"""
This is the main Orchestrator agent. This agent
will lead all other agents in their tasks and
will be the "conductor" of everything
"""

from IPython.display import Image, display
from langgraph.graph import StateGraph, END
import json
import os
from src.core.state import log_event, log_error, AgentState
from src.core.scope_guard import enforce_scope, ScopeViolationError
from src.core.llm_client import call_llm, load_prompt
# from src.agents.recon import recon_agent
# from src.agents.vuln import vuln_agent
# from src.agents.report import report_agent

def build_graph():
    """
    Build the LangGraph graph with all four agents.
    This graph will be ready to invoke with the agent state
    """

    workflow = StateGraph(AgentState)

    # Create the different agent nodes
    workflow.add_node('orchestrator', orchestrator_agent)
    # graph.add_node('recon', recon_agent)
    # graph.add_node('vuln_analyst', vuln_agent)
    # graph.add_node('report_writer', report_agent)

    # Commented code will be uncommented once other
    # agents have been made and can be tested

    # Set pipeline order
    workflow.set_entry_point('orchestrator')
    workflow.add_edge('orchestrator', END)
    # workflow.add_edge('orchestrator', 'recon')
    # workflow.add_edge('recon', 'vuln_analyst')
    # workflow.add_edge('vuln_analyst', 'report_writer')
    # workflow.add_edge('report_writer', END)

    # Compile the workflow into a graph
    graph = workflow.compile()

    # Generate a mermaid diagram of the graph
    # png_bytes = graph.get_graph().draw_mermaid_png()

    # # Make sure the output dir exist
    # os.makedirs("output", exist_ok=True)
    # with open("output/workflow_diagram.png", "wb") as file:
    #     file.write(png_bytes)

    # print("Returning graph")
    return graph

def orchestrator_agent(state: AgentState) -> dict:
    """
    Creates the Orchestrator agent node, which validates
    scope and dispatches all other agents
    """

    # Make sure that the given information is in scope
    try:
        enforce_scope(state['target_ip'], state['scope'])
    except ScopeViolationError as e:
        # Log Error
        error_update = log_error(state, 'orchestrator', str(e))
        return { **error_update, 'status': "Failed"}
    
    # Use the LLM to do a secondary scope check
    system_prompt = load_prompt(state, 'orchestrator', "orchestrator_system.txt")
    user_content = json.dumps({
        "task": "You are too plan and validate the penetration test pipeline",
        "target_ip": state['target_ip'],
        "scope": state['scope'],
        "allowed_ports": state['allowed_ports']
    })

    try:
        response = call_llm_with_retry(state, system_prompt, user_content, agent_name="orchestrator")

        # Printing for test purposes. Will be removed later
        
        print(f"\n[Orchestrator] Plan made and confirmed: {response}\n")

    except Exception as e:
        print(f"\n[Orchestrator] LLM call failed: {e}\n")

    # Log Event
    log_update = log_event(state, 'orchestrator', 
    f"Target IP of ({state['target_ip']}) in scope of ({state['scope']}). Starting agent pipeline")
    
    return { **log_update, 'status': "Running"}

def call_llm_with_retry(state: AgentState, system_prompt: str, user_content: str, agent_name: str, max_attempts=3) -> str:
    """
    This uses call_llm() with retry logic. Adds a message
    to the end of the prompt if the llm returns invalid
    JSON. This will run until it uses all of its attempts
    """
    retry_message = ""

    for attempt in range(1, max_attempts + 1):
        try:
            result = call_llm(state, system_prompt, user_content + retry_message, agent_name=agent_name)
            return result # successful call
        except json.JSONDecodeError as e:
            if attempt == max_attempts:
                raise RuntimeError(f"{agent_name}, failed after {max_attempts} attempts")
            retry_message = (
                "\n\n--- Correction Required ---\n"
                "Your previous response could not be parsed as valid JSON.\n"
                "The ERROR was {e}\n"
                "REQUIREMENT: Return ONLY VALID JSON. No Markdown. No Explanation. No Code Fences.\n"
                "--- End of Correction ---"
            )
