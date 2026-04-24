"""
This is the Vulnerability Analyst agent.
It takes the structured recon output and produces a list of vulnerabilities
using the LLM + CVE reference table from the prompt.
"""

import json
from src.core.state import AgentState, log_event, log_error, write_vuln
from src.core.llm_client import load_prompt
from .orchestrator import call_llm_with_retry

def vuln_agent(state: AgentState) -> dict:
    """
    Vulnerability Analyst node.
    Reads state['recon'], calls LLM with the vuln_analyst_system prompt,
    returns parsed list of vulnerabilities for state['vuln'].
    """
    updates = {}
    current_state = state
    agent = 'vuln_analyst'

    #Log: vuln_analyst started
    updates = {**updates, **log_event(current_state, agent, f"{agent.upper()} started")}
    current_state = {**state, **updates}

    # Verify we have recon data
    recon = state.get('recon', {})
    if not recon or not recon.get('open_ports'):
        err_msg = "No reconnaissance data found. Cannot perform vulnerability analysis."
        updates = {**updates, **log_error(current_state, agent, err_msg)}
        current_state = {**state, **updates}
        print(f"\n[Vuln Analyst] {err_msg}\n")
        return {**updates, 'status': "Failed"}
    
    # Use the LLM to find known vulnerabilities in recon findings
    system_prompt = load_prompt("vuln_analyst_system.txt")
    user_content = json.dumps({
        "task": "Analyze the following reconnaissance findings and produce a vulnerability list "
        "using the CVE reference table and rules in the system prompt.",
        "recon_findings": recon
    }, indent = 2)

    # Log: Call to LLM with input
    updates = {**updates, **log_event(current_state, agent, f"Calling LLM. Input: {user_content}")}
    current_state = {**state, **updates}

    try:
        response = call_llm_with_retry(system_prompt, user_content, agent_name=agent)

        vulnerabilities = response if isinstance(response, list) else []

        # Log: Successful LLM call with output
        updates = {**updates, **log_event(current_state, agent, f"Successful LLM call. Output: {response}")}
        current_state = {**state, **updates}

        # Write to state['vuln']
        updates = {**updates, **write_vuln(current_state, vulnerabilities)}

        print(f"\n[Vulnerability Analyst] {len(vulnerabilities)} vulnerabilities found.\n")

    except Exception as e:
        updates = {**updates, **log_error(current_state, agent, f"LLM call failed: {str(e)}")}
        current_state = {**state, **updates}
        print(f"\n[Vulnerability Analyst] LLM call failed: {e}\n")
        return {**updates, 'status': "Failed"}
    

    return {**updates, 'status': "Running"}

    

