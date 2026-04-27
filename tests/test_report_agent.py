#!/usr/bin/env python3
"""Standalone test for report_agent (HTML output version)."""

import os
import sys
from dotenv import load_dotenv

# Anchor to project root regardless of where this script is run from
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(script_dir, ".."))

if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.agents.report import report_agent
from src.core.state import initialise_state, AgentState

load_dotenv(os.path.join(project_root, ".env"))


def create_test_recon_data() -> dict:
    """Realistic recon data based on Metasploitable 2."""
    return {
        "scan_time": "2026-04-26T14:00:00Z",
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
        "whois_raw": "NetRange: 192.168.0.0 - 192.168.255.255\nNetName: PRIVATE-ADDRESS-CBLK-RFC1918",
        "nmap_raw": (
            "Starting Nmap 7.94\n"
            "Nmap scan report for 192.168.56.101\n"
            "21/tcp   open  ftp         vsftpd 2.3.4\n"
            "22/tcp   open  ssh         OpenSSH 4.7p1\n"
            "80/tcp   open  http        Apache httpd 2.2.8\n"
            "139/tcp  open  netbios-ssn Samba 3.0.20\n"
            "3306/tcp open  mysql       MySQL 5.0.51a\n"
        )
    }


def create_test_vuln_data() -> list:
    """Realistic vuln list matching vuln_agent output format."""
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
                "in the username field which opens a shell on port 6200."
            ),
            "evidence": "nmap detected vsftpd 2.3.4 running on port 21/tcp",
            "remediation": "Upgrade to vsftpd 2.3.5 or later immediately."
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
            "description": "OpenSSH 4.7p1 uses weak CBC mode ciphers susceptible to plaintext recovery.",
            "evidence": "nmap detected OpenSSH 4.7p1 on port 22/tcp",
            "remediation": "Upgrade to OpenSSH 8.x and disable weak ciphers in sshd_config."
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
            "description": "Apache 2.2.8 is vulnerable to a byte-range DoS via crafted Range headers.",
            "evidence": "nmap detected Apache httpd 2.2.8 on port 80/tcp",
            "remediation": "Upgrade to Apache 2.2.21 or later."
        },
        {
            "id": "VULN-004",
            "port": 139,
            "service": "netbios-ssn",
            "version": "Samba 3.0.20",
            "cve": "CVE-2007-2447",
            "cvss_score": 10.0,
            "severity": "Critical",
            "category": "Remote Code Execution",
            "description": (
                "Samba 3.0.20 allows RCE via shell metacharacters in the username "
                "field during MS-RPC calls."
            ),
            "evidence": "nmap detected Samba 3.0.20 on port 139/tcp",
            "remediation": "Upgrade Samba to 3.0.25 or later."
        },
        {
            "id": "VULN-005",
            "port": 3306,
            "service": "mysql",
            "version": "MySQL 5.0.51",
            "cve": None,
            "cvss_score": None,
            "severity": "High",
            "category": "No Authentication",
            "description": "MySQL root account has no password set, allowing unauthenticated access.",
            "evidence": "nmap detected MySQL 5.0.51 on port 3306/tcp",
            "remediation": "Set a strong root password and restrict remote access."
        }
    ]


def test_report_agent():
    print("=== Testing Report Writer Agent — HTML Output Version ===\n")

    # 1. Build initial state
    initial_state: AgentState = initialise_state(
        target_ip="192.168.56.101",
        scope="192.168.56.101/32",
        allowed_ports="1-65535"
    )

    # 2. Inject recon and vuln — simulates agents 2 and 3 having already run
    initial_state["recon"] = create_test_recon_data()
    initial_state["vuln"]  = create_test_vuln_data()

    print(f"Target IP           : {initial_state['target_ip']}")
    print(f"Scope               : {initial_state['scope']}")
    print(f"Vulns injected      : {len(initial_state['vuln'])}")
    print(f"Open ports injected : {len(initial_state['recon']['open_ports'])}\n")

    # 3. Run the agent
    print("Running report_agent...\n")
    updates = report_agent(initial_state)

    # 4. Merge delta into full state
    final_state = {**initial_state, **updates}

    # 5. Inspect results
    print("=== RESULTS ===")
    print(f"Status              : {final_state.get('status', 'UNKNOWN')}")

    report_html = final_state.get("report", "")

    if report_html and isinstance(report_html, str):
        print(f"Report type         : string (HTML)")
        print(f"Report length       : {len(report_html)} characters")

        # Basic checks on the HTML content
        checks = {
            "Has <html> tag":       "<html" in report_html.lower(),
            "Has <body> tag":       "<body" in report_html.lower(),
            "Has target IP":        "192.168.56.101" in report_html,
            "Has CVE-2011-2523":    "CVE-2011-2523" in report_html,
            "Has CVE-2007-2447":    "CVE-2007-2447" in report_html,
            "Has 'Critical'":       "Critical" in report_html,
        }

        print("\nContent checks:")
        all_passed = True
        for check, result in checks.items():
            status = "PASS" if result else "FAIL"
            if not result:
                all_passed = False
            print(f"  [{status}] {check}")

        if all_passed:
            print("\nAll checks passed.")
        else:
            print("\nSome checks failed — inspect output/report.html for details.")

        # Preview first 300 characters
        print(f"\nHTML preview (first 300 chars):\n{report_html[:300]}")

    else:
        print("FAIL: report is empty or not a string — LLM call likely failed.")

    # 6. Check errors
    errors = final_state.get("error", [])
    if errors:
        print(f"\nErrors ({len(errors)}):")
        for err in errors:
            print(f"  [{err.get('timestamp')}] {err.get('agent')}: {err.get('error_message')}")

    # 7. Event summary
    events = final_state.get("event", [])
    print(f"\nEvents logged       : {len(events)}")

    # 8. Save HTML report so you can open it in a browser
    os.makedirs("output", exist_ok=True)
    if report_html and isinstance(report_html, str):
        with open("output/report.html", "w", encoding="utf-8") as f:
            f.write(report_html)
        print("\nHTML report saved to: output/report.html")
        print("Open this file in a browser to preview the report.")

    return final_state


if __name__ == "__main__":
    test_report_agent()