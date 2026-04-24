#!/usr/bin/env python3
"""Standalone test for vuln_agent without needing recon_agent or full graph."""

import json
import os
import sys
from dotenv import load_dotenv


# Change to root directory
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))

if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.agents.vuln import vuln_agent
from src.core.state import initialise_state, AgentState

load_dotenv(os.path.join(project_root, ".env"))

def create_test_recon_data() -> dict:
    """Realistic recon data based on Metasploitable 2 + pseudocode examples"""
    return {
        "scan_time": "2026-04-22T16:41:00Z",
        "open_ports": [
            {
                "port": 21,
                "protocol": "tcp",
                "state": "open",
                "service": "ftp",
                "version": "vsftpd 2.3.4",
                "banner": "220 (vsFTPd 2.3.4)"
            },
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 4.7p1 Debian 8ubuntu1",
                "banner": None
            },
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "version": "Apache httpd 2.2.8",
                "banner": None
            },
            {
                "port": 139,
                "protocol": "tcp",
                "state": "open",
                "service": "netbios-ssn",
                "version": "Samba 3.0.20-Debian",
                "banner": None
            },
            {
                "port": 445,
                "protocol": "tcp",
                "state": "open",
                "service": "microsoft-ds",
                "version": "Samba 3.0.20-Debian",
                "banner": None
            },
            {
                "port": 3306,
                "protocol": "tcp",
                "state": "open",
                "service": "mysql",
                "version": "MySQL 5.0.51a-3ubuntu5",
                "banner": None
            }
        ],
        "os_detection": {
            "os_guess": "Linux 2.6.x",
            "confidence": "high"
        },
        "web_paths": ["/phpMyAdmin", "/dvwa", "/mutillidae"],
        "whois_raw": "Domain Name: example.com ... (truncated whois output)",
        "nmap_raw": "Full nmap output would be appended here..."
    }

def test_vuln_agent():
    print("=== Testing Vulnerability Analyst Agent (Standalone) ===\n")
    
    # 1. Create initial state using the correct initialise_state from state.py
    # CHANGED: Use list for allowed_ports to match current initialise_state signature
    initial_state: AgentState = initialise_state(
        target_ip="192.168.56.101",
        scope="192.168.56.101/32",
        allowed_ports=["1-65535"]
    )
    
    # 2. Inject realistic recon data into state['recon']
    # CHANGED: This is the key step — we manually populate recon so we can test vuln_agent alone
    recon_data = create_test_recon_data()
    initial_state["recon"] = recon_data
    
    print(f"Target IP       : {initial_state['target_ip']}")
    print(f"Scope           : {initial_state['scope']}")
    print(f"Open ports in test data : {len(recon_data['open_ports'])}\n")
    
    # 3. Run the vuln_agent directly (this calls your latest vuln.py)
    print("Running vuln_agent...\n")
    updated_state = vuln_agent(initial_state)
    
    # 4. Inspect results
    print("=== VULN AGENT RESULTS ===")
    print(f"Final Status          : {updated_state.get('status', 'UNKNOWN')}")
    
    # CHANGED: Use correct key "vuln" instead of old "vulnerabilities"
    vulnerabilities = updated_state.get("vuln", [])
    print(f"Generated vulnerabilities : {len(vulnerabilities)}\n")
    
    if vulnerabilities:
        print("Vulnerability Findings:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"{i:2d}. [{vuln.get('severity', 'N/A')}] Port {vuln.get('port')} | "
                  f"{vuln.get('service')} | {vuln.get('cve', 'No CVE')} | "
                  f"{vuln.get('category', 'N/A')}")
    else:
        print("WARNING: No vulnerabilities were generated!")
    
    # Check for errors
    # CHANGED: Use correct key "error" (singular) from current state.py
    errors = updated_state.get("error", [])
    if errors:
        print(f"\nErrors encountered: {len(errors)}")
        for err in errors:
            print(f"  - [{err.get('timestamp')}] {err.get('agent')}: {err.get('error_message')}")
    
    # CHANGED: Also check event logs for debugging
    events = updated_state.get("event", [])
    print(f"\nTotal events logged : {len(events)}")
    
    # Save full state for inspection
    os.makedirs("output", exist_ok=True)
    with open("output/test_vuln_output.json", "w") as f:
        json.dump(updated_state, f, indent=2, default=str)
    
    print("\nFull updated state saved to: output/test_vuln_output.json")
    print("You can inspect this file to verify state['vuln'] and logs.")
    
    return updated_state

if __name__ == "__main__":
    test_vuln_agent()