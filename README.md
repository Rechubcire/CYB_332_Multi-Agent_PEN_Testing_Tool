# Multi-Agent Penetration Testing Tool

## Project Overview 
<p>This project is a Python-based, multi-agent LLM penetration testing tool designed to automate the stages of a penetration test against a controlled, isolated target environment. This tool contains four agents that are each responsible for a distinct phase of the penetration testing lifecycle. The agent then communicates its findings to the downstream agents. This tool will leverage the Anthropic Claude API for reasoning and decision-making. The tool coordinates each agent to perform their tasks. This is all done in the Metasploitable 2 environment.</p>

## System Architecture
<p>The tool utilizes a centralized state-management pattern where agents interact through a shared JSON state object.</p>

<ul>
  <li><strong>Orchestrator Agent:</strong> The "brain" of the opperation. Recives the target scope, plans the task sequence, dispatches agents, and aggregates their outputs into a final report.</li>
  
  <li><strong>Reconnaissance Agent:</strong> Performs passive and active recon on the Metasploitable 2 environment and returns findings in a JSON file. Executes tools such as: port scanning, service enumeration, and OS detection.</li>
  
  <li><strong>Vulnerability Analyst Agent:</strong> Takes output from recon agent and reasons about potential attack surfaces and maps findings to known vulnerability classes</li>
  
  <li><strong>Report Writer Agent:</strong> Gathers all agent findings into one professionally structured penetration testing report with risk ratings, evidence, and remediation advice.</li>
  
</ul>

## Technical Stack

<ul>
  <li><strong>Language:</strong> Python 3.10+</li>
  <li><strong>LLM Integration:</strong> Abthropic Claude API </li>
  <li><strong>Targeted Environment:</strong> Metasploitable 2</li>
  <li><strong>State Management:</strong> JSON-based shared memory</li>
</ul>

## Security & Scope Constraints 

<ul>
  <li><strong>Scope Enforcement:</strong> The Orchestrator agent is given the IP address of the lab VM and is only to attack this machine.</li>

  <li><strong>Isolation:</strong> All testing is conducted via a VirtualBox Host-only or Internal Network to prevent accidental external interfaces.</li>

  <li><strong>Vulnerability Handling:</strong> This agent will NOT exploit any vulnerability found. The agent's defined scope is to discover and analyze vulnerabilities, not to actively exploit them.</li>
</ul>

## Project Structure

    ├── src/
    |   ├── agents/
    |   |   ├── orchestrator.py    # Scope enforcement and agent coordinator
    |   |   ├── reconnaissance.py  # Tool wrappers and information gathering
    |   |   ├── analyst.py         # CVE Mapping and analysis
    |   |   └── reporter.py        # Documentation/PDF Report generator
    |   ├── core/
    |   |   ├── state_managment.py # JSON state handler
    |   |   └── llm_integration.py # Claude Integration
    |   └── main.py                # Entry point and main interface
    ├── docs/                      # Documents and graphs
    ├── tests/                     # Unit test for agent logic
    ├── .env.example               # Template for API keys and environment variables
    ├── requirements.txt           # Dependencies used by agents
    └── README.md                  

## Setup & Installation
<ol>
  <li></li>
</ol>

## Team Members

<ul>
  <li><strong>Eric Bucher</strong></li>
  <li><strong>Max Boon</strong></li>
  <li><strong>Will Gilkey</strong></li>
  <li><strong>Connor Martin</strong></li>
  <li><strong>Kris Kuusik</strong></li>
</ul>
