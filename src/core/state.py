"""
 Shared state file, created by Orchestrator Agent and sent to
 all other agents where they fill out their specific section.
 This is used to insure a consistent JSON state between agents.
"""

import uuid
from typing import TypedDict, Dict, List
from datetime import datetime, timezone
import json
import os

class AgentState(TypedDict):
    # Meta data Orch initializes at start up
    session_id: str
    timestamp: str
    target_ip: str
    scope: str
    allowed_ports: str
    status: str

    # Model specific state info
    recon: Dict
    vuln: List
    report: str

    # Logs
    error: List
    event: List

def initialise_state(target_ip: str, scope: str, allowed_ports: list) -> AgentState:
    """
    Called by the Orchestrator agent to initialise the set
    JSON state. Other agents to fill in recon, vuln, and report

    Meta data is initialized with a session id, timestamp, target_ip,
    scope, allowed_ports, and tool status.
    """

    return AgentState(
        
        session_id = str(uuid.uuid4()),
        timestamp = datetime.now(timezone.utc).isoformat(),
        target_ip = target_ip,
        scope = scope,
        allowed_ports = allowed_ports,
        status = "Pending", # [Pending, Running, Complete, Failed]

        recon = {}, # scan_time, open_ports, os_detection, web_paths, whois_raw, nmap_raw
        vuln = [], # list of dict containing (id, port, service, severity, cve)
        report = None, # html string of the report containing executive_summary, scope_and_methodology, findings, risk_matrix, risk_rating_overall

        error = [], # list of dict containing (timestamp, agent, error_message)
        event = [] # list of dict containing (timestamp, agent, event_message)
    )

def update_status(state: AgentState, status: str) -> dict:
    """
    Given a state and a status update the status of the given state
    to the given status. This is done when running certain agents and
    updating the status to reflect what is happening.
    """
    return { "status": status}

def write_recon(state: AgentState, recon_data: dict) -> dict:
    """
    Write the recon agent's output into state["recon"]
    Called by agent 2 (recon) after the tool has 
    executed and LLM parsing
    """
    return { "recon": recon_data}

def write_vuln(state: AgentState, vulnerabilities: list) -> dict:
    """
    Writes the output from agent 3 (vuln) after analysis
    and reasoning by the LLM
    """
    return { "vuln": vulnerabilities}

def write_report(state: AgentState, report_html: str) -> dict:
    """
    Writes the output from agent 4 (report writer)
    to the JSON state
    """
    return { "report": report_html}

def log_event(state:dict, agent: str, message: str) -> dict:
    """
    Create a event log dictionary containing a timestamp,
    agent in use, and the log message. Add it to the JSON state.
    """
    event_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent, # Agent in use at time of event
        "event_message": message
    }

    return { "event": state["event"] + [event_entry]}

def log_error(state: AgentState, agent:str, error_message: str) -> dict:
    """
    Create an error log when an error occurs, includes a
    timestamp, the agent in use, and an error message
    Add it to the errors in the JSON state
    """
    error_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent, # Agent in use at time of error
        "error_message": error_message
    }

    return { "error": state["error"] + [error_entry]}    

def save_event_log(state: AgentState, path="output/run_events.log") -> None:
    """
    Creates a log of all of the events and errors
    This is then saved to help debugging
    """
    os.makedirs("output", exist_ok=True)
    with open(path, 'w') as file:
        for entry in state.get('event', []):
            file.write(json.dumps(entry) + '\n')
        for entry in state.get('error', []):
            file.write(json.dumps(entry) + '\n')

def save_report_to_disk(report_html: str, path="output/final_report.pdf") -> None:
    """
    Take the html code from the LLM output and 
    convert it to a pdf and then write it to 
    the predefined path.
    """
    from weasyprint import HTML

    HTML(string=report_html).write_pdf(path)

def save_state_to_disk(state: AgentState, path="output/state.json") -> None:
    """
    Check to see if a state file exist, if not create it
    add the serialize JSON state to the state.json file
    save the JSON file to the output folder
    """
    # Make sure the output dir exists
    os.makedirs("output", exist_ok=True)

    with open(path, 'w') as file:# Open file from provided path as write

        # Serialize the state as JSON
        json_string = json.dumps(state, indent=2, default=str)

        file.write(json_string)
    
    save_event_log(state)


    

def validate_section(state: AgentState, section: str) -> bool:
    """
    Checks all sections to make sure they have the
    correct structure and that they exist
    """
    if section == "recon":
        if not isinstance(state["recon"].get("scan_time"), str):
            return False
        if not isinstance(state["recon"].get("open_ports"), list):
            return False
        if not isinstance(state["recon"].get("os_detection"), dict):
            return False
        if not isinstance(state["recon"].get("web_paths"), list):
            return False
        if not isinstance(state["recon"].get("whois_raw"), str):
            return False
        if not isinstance(state["recon"].get("nmap_raw"), str):
            return False
        
        # If everything exist and is the correct type return True
        return True
    
    elif section == "vuln":
        if not isinstance(state["vuln"], list):
            return False
        if not state["vuln"]: # Check to see if the list is empty
            return False
        for entry in state["vuln"]:
            if not isinstance(entry, dict):
                return False
            if not "id" in entry:
                return False
            if not "port" in entry:
                return False
            if not "service" in entry:
                return False
            if not "severity" in entry:
                return False
            if not "cve" in entry:
                return False
            
        # vuln is a non-empty list of dicts, and each dict
        # contains the keys (id, port, service, severity, cve)
        return True
    
    elif section == "report":
        if not isinstance(state["report"], str):
            return False
        if not state["report"]:
            return False
        
        # All items are present and not empty
        return True
    
    else:
        # Section name is unknown
        return False