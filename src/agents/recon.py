"""
This is the primary recon agent
this agent will run all of the reconissance tools against
the target and give the results in a JSON format for analysis
"""

import json
from src.core.state import log_event, log_error, AgentState
from src.core.scope_guard import enforce_scope, ScopeViolationError
from src.core.llm_client import call_llm, load_prompt
from src.agents.orchestrator import call_llm_with_retry
from tools.nmap_wrapper import run_nmap
from tools.gobuster_wrapper import run_gobuster
from tools.curl_wrapper import grab_http_headers
from tools.whois_wrapper import run_whois

def recon_agent(state: AgentState) -> dict:
    """
    Runs all recon tools against the target, then calls the LLM
    to extract the structured JSON from the combined outputs.
    Returns the state update to the orchestrator
    """
    print("Reconnaissance Started \n")
    
    # Event logging variables
    updates = {}
    current_state = state
    agent = 'recon'

    # Log: Recon started
    updates = {**updates, **log_event(current_state, agent, f"{agent.upper()} started.")}
    current_state = {**state, **updates}

    # Make sure that the given information is in scope
    try:
        enforce_scope(state['target_ip'], state['scope'])

        # Log: target IP in scope
        updates = {**updates, **log_event(current_state, agent, f"Scope validation passed. {state['target_ip']} is in scope.")}
        current_state = {**state, **updates}

    except ScopeViolationError as e:

        # Log: target IP out of scope
        updates = {**updates, **log_error(current_state, agent, str(e))}
        return {**updates, 'status': 'Failed'}

    target = state["target_ip"]
    scope = state["scope"]
    ports = state["allowed_ports"]

    # Run all four recon tools against the target
    try:
        nmap_result = run_nmap(target, ports, scope)

        # Log: nmap complete
        updates = {**updates, **log_event(current_state, agent, "nmap complete.")}
        current_state = {**state, **updates}

        gobuster_result = run_gobuster(target, 80, scope)

        # Log: gobuster complete
        updates = {**updates, **log_event(current_state, agent, "gobuster port 80 complete.")}
        current_state = {**state, **updates}

        curl_result = grab_http_headers(target, 80, scope)

        # Log: curl complete
        updates = {**updates, **log_event(current_state, agent, "curl port 80 complete.")}
        current_state = {**state, **updates}

        whois_result = run_whois(target)

        # Log: whois complete
        updates = {**updates, **log_event(current_state, agent, "whois complete.")}
        current_state = {**state, **updates}

        # If port 8180 is detected, also scan it
        if "8180" in nmap_result:
            gobuster_result_8180 = run_gobuster(target, 8180, scope)
            curl_result_8180 = grab_http_headers(target, 8180, scope)
            gobuster_result += "\n\n--- Port 8180 Results ---\n" + gobuster_result_8180
            curl_result += "\n\n--- Port 8180 Results ---\n" + curl_result_8180

            # Log: port 8180 scan complete
            updates = {**updates, **log_event(current_state, agent, "Port 8180 scan complete.")}
            current_state = {**state, **updates}

    except Exception as e:

        # Log: Error during tool execution
        updates = {**updates, **log_error(current_state, agent, f"Tool execution failed. Error: {str(e)}")}
        return {**updates, 'status': 'Failed'}

    # Send all raw tool output to LLM for structured extraction
    user_content = (
        "Parse the following raw security tool output into structured JSON.\n"
        "Extract ALL open ports. Use null for any unknown field.\n\n"
        "--- NMAP XML OUTPUT ---\n"     + nmap_result +
        "\n\n--- GOBUSTER OUTPUT ---\n" + gobuster_result +
        "\n\n--- CURL HEADERS ---\n"    + curl_result +
        "\n\n--- WHOIS OUTPUT ---\n"    + whois_result +
        "\n\nReturn ONLY the recon JSON object. No markdown. No explanation."
    )

    recon_prompt = load_prompt("recon_system.txt")

    # Log: Call to LLM with input
    updates = {**updates, **log_event(current_state, agent, f"Calling LLM. Input length: {len(user_content)}")}
    current_state = {**state, **updates}

    try:
        recon_data = call_llm_with_retry(recon_prompt, user_content, agent_name=agent)

        # Log: Successful LLM call with output
        updates = {**updates, **log_event(current_state, agent, f"Successful LLM call.")}
        current_state = {**state, **updates}

    except Exception as e:

        # Log: Error when calling the LLM with exception
        updates = {**updates, **log_error(current_state, agent, f"Error occurred when calling the LLM. Error: {str(e)}")}
        return {**updates, 'status': 'Failed'}

    # Attach raw outputs for report appendix
    recon_data["nmap_raw"] = nmap_result
    recon_data["whois_raw"] = whois_result
    recon_data["gobuster_raw"] = gobuster_result
    recon_data["curl_raw"] = curl_result

    # Log: Recon complete
    updates = {**updates, **log_event(current_state, agent, "Recon complete.")}

    return {**updates, "recon": recon_data, "status": "Running"}