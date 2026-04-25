#!/usr/bin/env python3
"""Standalone test for report_agent without needing recon_agent or full graph."""

import json
import os
import sys
from dotenv import load_dotenv

# Change to root directory
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))

if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.agents.report import report_agent
from src.core.state import initialise_state, AgentState, save_state_to_disk

load_dotenv(os.path.join(project_root, ".env"))


def create_test_recon_data() -> dict:
    """Realistic recon data based on Metasploitable 2."""
    return {
        "scan_time": "2026-04-25T14:00:00Z",
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
            "guess": "Linux 2.6.x",
            "confidence": 90
        },
        "web_paths": ["/phpMyAdmin", "/dvwa", "/mutillidae"],
        "whois_raw": "NetRange: 192.168.0.0 - 192.168.255.255\nCIDR: 192.168.0.0/16\nNetName: PRIVATE-ADDRESS-CBLK-RFC1918-IANA-RESERVED",
        "nmap_raw": (
            "Starting Nmap 7.94 ( https://nmap.org )\n"
            "Nmap scan report for 192.168.56.101\n"
            "Host is up (0.00040s latency).\n"
            "PORT     STATE SERVICE     VERSION\n"
            "21/tcp   open  ftp         vsftpd 2.3.4\n"
            "22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1\n"
            "80/tcp   open  http        Apache httpd 2.2.8\n"
            "139/tcp  open  netbios-ssn Samba 3.0.20-Debian\n"
            "445/tcp  open  microsoft-ds Samba 3.0.20-Debian\n"
            "3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5\n"
            "Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds"
        )
    }


def create_test_vuln_data() -> list:
    """
    Realistic vuln list matching the output format of vuln_agent.
    Key name is 'vuln' to match AgentState schema.
    """
    return [
        {
            "id": "VULN-001",
            "port": 21,
            "service": "ftp",
            "version": "vsftpd 2.3.4",
            "cve": "CVE-2011-2523",
            "cvss_score": 10.0,
            "severity": "Critical",
            "category": "Remote Code Execution — Backdoor",
            "description": (
                "vsftpd 2.3.4 contains a backdoor triggered by a smiley face "
                "in the username field (USER :)) which opens a shell on port 6200."
            ),
            "evidence": "nmap detected vsftpd 2.3.4 running on port 21/tcp",
            "remediation": "Upgrade to vsftpd 2.3.5 or later. Remove the compromised binary."
        },
        {
            "id": "VULN-002",
            "port": 22,
            "service": "ssh",
            "version": "OpenSSH 4.7p1",
            "cve": "CVE-2008-5161",
            "cvss_score": 2.6,
            "severity": "Low",
            "category": "Weak Crypto",
            "description": "OpenSSH 4.7p1 uses weak cryptographic algorithms susceptible to CBC mode attacks.",
            "evidence": "nmap detected OpenSSH 4.7p1 running on port 22/tcp",
            "remediation": "Upgrade to OpenSSH 8.x or later and disable weak ciphers."
        },
        {
            "id": "VULN-003",
            "port": 80,
            "service": "http",
            "version": "Apache httpd 2.2.8",
            "cve": "CVE-2011-3192",
            "cvss_score": 7.8,
            "severity": "High",
            "category": "Denial of Service",
            "description": "Apache 2.2.8 is vulnerable to a byte-range DoS attack via crafted Range headers.",
            "evidence": "nmap detected Apache httpd 2.2.8 running on port 80/tcp",
            "remediation": "Upgrade to Apache 2.2.21 or later. Apply vendor patch."
        },
        {
            "id": "VULN-004",
            "port": 139,
            "service": "netbios-ssn",
            "version": "Samba 3.0.20",
            "cve": "CVE-2007-2447",
            "cvss_score": 10.0,
            "severity": "Critical",
            "category": "Remote Code Execution — Username Map Script",
            "description": (
                "Samba 3.0.20 allows attackers to execute arbitrary commands by sending "
                "shell metacharacters in the username during authentication."
            ),
            "evidence": "nmap detected Samba 3.0.20 on ports 139 and 445",
            "remediation": "Upgrade Samba to >= 3.0.25. Disable the username map script option."
        },
        {
            "id": "VULN-005",
            "port": 445,
            "service": "microsoft-ds",
            "version": "Samba 3.0.20",
            "cve": "CVE-2007-2447",
            "cvss_score": 10.0,
            "severity": "Critical",
            "category": "Remote Code Execution — Username Map Script",
            "description": (
                "Samba 3.0.20 allows attackers to execute arbitrary commands by sending "
                "shell metacharacters in the username during authentication."
            ),
            "evidence": "nmap detected Samba 3.0.20 on ports 139 and 445",
            "remediation": "Upgrade Samba to >= 3.0.25. Disable the username map script option."
        },
        {
            "id": "VULN-006",
            "port": 3306,
            "service": "mysql",
            "version": "MySQL 5.0.51",
            "cve": None,
            "cvss_score": None,
            "severity": "High",
            "category": "No Authentication",
            "description": "MySQL 5.0.51 has no root password set by default, allowing unauthenticated access.",
            "evidence": "nmap detected MySQL 5.0.51 running on port 3306/tcp",
            "remediation": "Set a strong root password. Restrict remote MySQL access via firewall rules."
        }
    ]


def test_report_agent():
    print("=== Testing Report Writer Agent (Standalone) ===\n")

    # 1. Build initial state
    initial_state: AgentState = initialise_state(
        target_ip="192.168.56.101",
        scope="192.168.56.101/32",
        allowed_ports=["1-65535"]
    )

    # 2. Inject recon and vuln data — simulates what agents 2 and 3 would have written
    initial_state["recon"] = create_test_recon_data()
    initial_state["vuln"] = create_test_vuln_data()

    print(f"Target IP              : {initial_state['target_ip']}")
    print(f"Scope                  : {initial_state['scope']}")
    print(f"Vulns in test data     : {len(initial_state['vuln'])}")
    print(f"Open ports in recon    : {len(initial_state['recon']['open_ports'])}\n")

    # 3. Run the report_agent directly
    print("Running report_agent...\n")
    updates = report_agent(initial_state)

    # 4. Merge delta into full state (LangGraph does this automatically in the pipeline)
    final_state = {**initial_state, **updates}

    # 5. Inspect results
    print("=== REPORT AGENT RESULTS ===")
    print(f"Final status           : {final_state.get('status', 'UNKNOWN')}")

    report = final_state.get("report", {})
    print(f"Report keys present    : {list(report.keys())}\n")

    if report.get("executive_summary"):
        summary_preview = report["executive_summary"][:200].replace("\n", " ")
        print(f"Executive summary preview:\n  {summary_preview}...\n")
    else:
        print("WARNING: executive_summary is empty or missing!\n")

    risk_matrix = report.get("risk_matrix", {})
    overall = report.get("risk_rating_overall", "MISSING")
    print(f"Overall risk rating    : {overall}")
    print(f"Risk matrix            : {risk_matrix}\n")

    findings = report.get("findings", [])
    print(f"Findings in report     : {len(findings)}")
    if findings:
        print("Findings list:")
        for i, f in enumerate(findings, 1):
            print(f"  {i:2d}. [{f.get('severity', 'N/A')}] {f.get('title', 'No title')} | CVE: {f.get('cve', 'N/A')}")
    else:
        print("WARNING: No findings in report — check that state['vuln'] key is correct in report_agent!")

    # 6. Check for errors
    errors = final_state.get("error", [])
    if errors:
        print(f"\nErrors encountered: {len(errors)}")
        for err in errors:
            print(f"  - [{err.get('timestamp')}] {err.get('agent')}: {err.get('error_message')}")

    # 7. Event log summary
    events = final_state.get("event", [])
    print(f"\nTotal events logged    : {len(events)}")

    # 8. Save full merged state for inspection
    os.makedirs("output", exist_ok=True)
    with open("output/test_report_output.json", "w") as f:
        json.dump(final_state, f, indent=2, default=str)

    print("\nFull merged state saved to: output/test_report_output.json")
    print("Inspect state['report'] to verify all fields are present.")

    return final_state


if __name__ == "__main__":
    test_report_agent()