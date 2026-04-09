"""
 Shared state file, created by Orchestrator Agent and sent to
 all other agents where they fill out their specific section.
 This is used to insure a consistent JSON state between agents.
"""

import uuid
from datetime import datetime, timezone
import json
import os

def initialise_state(target_ip: str, scope: str, allowed_ports: list) -> dict:
    """
    Called by the Orchestrator agent to initialise the set
    JSON state. Other agents to fill in recon, vuln, and report

    Meta data is initialized with a session id, timestamp, target_ip,
    scope, allowed_ports, and tool status.
    """

    return {
        "meta": {
            "session_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_ip": target_ip,
            "scope": scope,
            "allowed_ports": allowed_ports,
            "status": "Pending" # [Pending, Running, Complete, Failed]
        },
        "recon": {}, # scan_time, open_ports, os_detection, web_paths, whois_raw, nmap_raw
        "vuln": [], # list of dict containing (id, port, service, severity, cve)
        "report": {}, # executive_summary, scope_and_methodology, findings, risk_matrix, risk_rating_overall
        "errors": [], # list of dict containing (timestamp, agent, error_message)
        "logs": [] # list of dict containing (timestamp, agent, event_message)
    }

def update_status(state: dict, status: str) -> None:
    """
    Given a state and a status update the status of the given state
    to the given status. This is done when running certain agents and
    updating the status to reflect what is happening.
    """
    state["meta"]["status"] = status

def write_recon(state: dict, recon_data: dict) -> None:
    """
    Write the recon agent's output into state["recon"]
    Called by agent 2 (recon) after the tool has 
    executed and LLM parsing
    """
    state["recon"] = recon_data

def write_vuln(state: dict, vulnerabilities: list) -> None:
    """
    Writes the output from agent 3 (vuln) after analysis
    and reasoning by the LLM
    """
    state["vuln"] = vulnerabilities

def write_report(state: dict, report_data: dict) -> None:
    """
    Writes the output from agent 4 (report writer)
    to the JSON state
    """
    state["report"] = report_data

def log_event(state:dict, agent: str, message: str) -> None:
    """
    Create a event log dictionary containing a timestamp,
    agent in use, and the log message. Add it to the JSON state.
    """
    event_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent, # Agent in use at time of event
        "event_message": message
    }

    state["logs"].append(event_entry)

def log_error(state: dict, agent:str, error_message: str) -> None:
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

    state["errors"].append(error_entry)

def save_state_to_disk(state: dict, path="output/state.json") -> None:
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


    

def validate_section(state: dict, section: str) -> bool:
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
        if not isinstance(state["report"].get("executive_summary"), str):
            return False
        if not isinstance(state["report"].get("scope_and_methodology"), str):
            return False
        if not isinstance(state["report"].get("findings"), list):
            return False
        if not isinstance(state["report"].get("risk_matrix"), dict):
            return False
        if not isinstance(state["report"].get("risk_rating_overall"), str):
            return False
        
        # All items are present and not empty
        return True
    
    else:
        # Section name is unknown
        return False