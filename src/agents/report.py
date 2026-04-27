import json
from typing import Any

from src.core.llm_client import call_llm_with_retry, load_prompt, call_llm
from src.core.state import AgentState, log_event, log_error, write_report



# Public node function — registered in build_graph() as 'report_writer'

def report_agent(state: AgentState) -> dict:
    """
    LangGraph node function — Node 4 of 4.
    """
    updates = {}
    current_state = state
    agent = "report_writer"
    vulns = state.get("vuln", [])
    recon = state.get("recon", {})

    # Log the start of this node
    updates = {**updates, **log_event(current_state, agent, f"{agent} starting")}
    current_state = {**state, **updates}

    # Extra log info from starting of agent
    updates ={**updates, **log_event(current_state, agent, f"Writing a report on {len(vulns)} finding(s) against {state['target_ip']}.")} 
    current_state = {**state, **updates}

    # Pre-compute risk matrix so the LLM does not have to count
    risk_counts = _count_severities(vulns)
    overall_risk = _determine_overall_risk(risk_counts)

    # Pull safe defaults from recon (fields may be absent if recon failed)
    scan_time = recon.get("scan_time") or state.get("timestamp", "unknown")
    os_guess  = (recon.get("os_detection") or {}).get("guess", "unknown")
    web_paths = recon.get("web_paths", [])

    # Gather the system and user prompt
    system_prompt = load_prompt("report_writer_system.txt")

    user_content = (
        "Write a complete, professional penetration test report\n"
        "based on the data below. Follow the report schema in your system prompt.\n\n"
        f"TARGET SCOPE:   {state['scope']}\n"
        f"SCAN DATE:      {scan_time}\n"
        f"ALLOWED PORTS:  {state['allowed_ports']}\n"
        f"OVERALL RISK:   {overall_risk}\n\n"
        "VULNERABILITIES FOUND:\n"
        + json.dumps(vulns, indent=2)
        + "\n\nOPEN PORTS SUMMARY:\n"
        + json.dumps(recon.get("open_ports", []), indent=2)
        + f"\n\nOS DETECTED: {os_guess}"
        + "\n\nRISK MATRIX: "
        + json.dumps(risk_counts)
        + "\n\nWEB PATHS FOUND: "
        + str(web_paths)
        + "\n\nReturn ONLY a COMPLETE HTML document with inline CSS styling. No markdown. No explanation text outside the HTML."
    )
    
    updates = {**updates, **log_event(current_state, agent, f"Calling LLM to create JSON report data. Input: {user_content}")}
    current_state = {**state, **updates}
    # Call the LLM with retry logic
    try:
        report_html = call_llm_with_retry(system_prompt, user_content, "report_writer", parse_json=False)
        
        updates = {**updates, **log_event(current_state, agent, f"Successful LLM call. Report Data Output: {report_html}")}
        current_state = {**state, **updates}
    except Exception as e:
        updates = {**updates, **log_error(current_state, agent, f"Error occurred when calling the LLM. Error: {str(e)}")}
        current_state = {**state, **updates}

        return {**updates, "status": "Failed"}

    

    updates = {**updates, **write_report(state, report_html)}

    # Return partial state update — LangGraph merges automatically
    return {**updates, "status": "complete",}


# Private helpers

def _count_severities(vuln_list: list) -> dict:
    """
    Counts how many vulnerabilities fall into each severity bucket.

    Args:
        vuln_list: List of vulnerability dicts from state['vulnerabilities']

    Returns:
        Dict with keys Critical, High, Medium, Low, Info and integer counts
    """
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in vuln_list:
        severity = vuln.get("severity", "Info")
        if severity in counts:
            counts[severity] += 1
        else:
            # Unknown severity — treat conservatively as Info
            counts["Info"] += 1
    return counts


def _determine_overall_risk(risk_counts: dict) -> str:
    """
    Returns the highest severity that has at least one finding.

    Walk from most severe to least severe so the first non-zero bucket wins.
    Falls back to 'Info' if no findings exist at all.

    Args:
        risk_counts: Output of _count_severities()

    Returns:
        One of: 'Critical', 'High', 'Medium', 'Low', 'Info'
    """
    for level in ["Critical", "High", "Medium", "Low"]:
        if risk_counts.get(level, 0) > 0:
            return level
    return "Info"