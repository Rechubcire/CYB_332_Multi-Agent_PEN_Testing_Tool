# Multi-Agent Penetration Testing Tool

##  Project Overview 
<p>This project is a Python-based, multi-agent LLM penetration testing tool designed to automate the stages of a penetration test against a controlled, isolated target environment. This tool contains four agents that are each responsible for a distinct phase of the penetration testing lifecycle. The agent then communicates its findings to the downstream agents. This tool will leverage the Anthropic Claude API for reasoning and decision-making. The tool coordinates each agent to perform their tasks. This is all done in the Metasploitable 2 environment.</p>

##  System Architecture
<p>The tool utilizes a centralized state-management pattern where agents interact through a shared JSON state object.</p>

<ul>
  <li><strong>Orchestrator Agent:</strong> The "brain" of the opperation. Recives the target scope, plans the task sequence, dispatches agents, and aggregates their outputs into a final report.</li>
  
  <li><strong>Reconnaissance Agent:</strong> Performs passive and active recon on the Metasploitable 2 environment and returns findings in a JSON file. Executes tools such as: port scanning, service enumeration, and OS detection.</li>
  
  <li><strong>Vulnerability Analyst Agent:</strong> Takes output from recon agent and reasons about potential attack surfaces and maps findings to known vulnerability classes</li>
  
  <li><strong>Report Writer Agent:</strong> Gathers all agent findings into one professionally structured penetration testing report with risk ratings, evidence, and remediation advice.</li>
  
</ul>

##  Technical Stack

<ul>
  <li><strong>Language:</strong> Python 3.10+</li>
  <li><strong>LLM Integration:</strong> Anthropic Claude API </li>
  <li><strong>Targeted Environment:</strong> Metasploitable 2</li>
  <li><strong>State Management:</strong> JSON-based shared memory</li>
</ul>

## Security & Scope Constraints 

<ul>
  <li><strong>Scope Enforcement:</strong> The Orchestrator agent is given the IP address of the lab VM and is only to attack this machine.</li>

  <li><strong>Isolation:</strong> All testing is conducted via a VirtualBox Host-only or Internal Network to prevent accidental external interfaces.</li>

  <li><strong>Vulnerability Handling:</strong> This agent will NOT exploit any vulnerability found. The agent's defined scope is to discover and analyze vulnerabilities, not to actively exploit them.</li>
</ul>

##  Project Structure

    ├── src/
    │   ├── agents/
    │   │   ├── orchestrator.py        # Scope enforcement and agent coordinator
    │   │   ├── recon.py               # Tool wrappers and information gathering
    │   │   ├── vuln.py                # CVE mapping and vulnerability analysis
    │   │   └── report.py              # Pentest report generator
    │   └── core/
    │       ├── state.py               # JSON state handler
    │       ├── llm_client.py          # Claude/LLM integration
    │       └── scope_guard.py         # Scope validation and enforcement
    │ 
    ├── tools/
    │   ├── nmap_wrapper.py            # nmap subprocess wrapper
    │   ├── gobuster_wrapper.py        # gobuster subprocess wrapper
    │   ├── curl_wrapper.py            # curl HTTP header grabber
    │   └── whois_wrapper.py           # whois lookup wrapper
    ├── prompts/
    │   ├── orchestrator_system.txt    
    │   ├── recon_system.txt           
    │   ├── vuln_analyst_system.txt    
    │   └── report_writer_system.txt   
    ├── tests/        
    |   ├── test_placeholder.py
    |   ├── test_report_agent.py
    |   ├── test_vuln_agent.py
    │   └── test_scope_guard.py       
    ├── output/                        # Created at runtime — add to .gitignore
    │   ├── state.json                 # Full state object from completed run
    |   ├── final_report.pdf           # Executive report from running tool
    │   ├── report.txt                 # Human-readable pentest report
    |   ├── run_events.log             # All events, including errors and regular events
    │   └── run.log                    # All LLM calls and tool outputs
    ├── main.py                        # Entry point and main interface
    ├── .env.example                   # Template for API keys and env variables
    ├── .gitignore                     # Must include .env and output/
    ├── requirements.txt               # Python dependencies
    ├── common.txt                     # Word file for GoBuster tool
    └── README.md

##  Linux Setup & Installation

<p><strong>Install Tools</strong></p>

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-venv
sudo apt install -y python3 python3-pip
sudo apt install -y git
sudo apt install -y nmap
sudo apt install -y gobuster
sudo apt install -y curl
sudo apt install -y whois
```

<p><strong>Clone the Repository</strong></p>

```bash
git clone https://github.com/Rechubcire/CYB_332_Multi-Agent_PEN_Testing_Tool.git
```

<p>Navigate to the folder and Ensure All Files are there</p>

```bash
cd CYB_332_Multi-Agent_PEN_Testing_Tool
ls
```


<p><strong>Create a Virtual Environment</strong></p>
<p>Make sure you are in the tool folder</p>

```bash
python3 -m venv venv
```
<p>Activate the Virtual Environment</p>

```bash
source venv/bin/activate
```
<p><strong>Create your .env file</strong></p>

```
nano .env.example
```
<p>Once you are in the .env.example file change the provider to either "gorq" or "anthropic" depending on what model you are using. Next, enter your API keys for the provider(s) you are using. Once you have entered your API keys and selected your provider save the file as ".env" and exit.</p>

<p><strong>Commands to save and write the .env file</strong></p>

```
Ctrl + o
#Change name from ".env.example" to ".env"
Enter
Ctrl + x
```

<p><strong>Run the requirements.txt file to install all of the Python dependencies</strong></p>

```
pip install -r requirements.txt
```

<p><strong>Run the tool command</strong></p>
<p>Make sure that you are in the tool folder when running this command</p>

```
python main.py --target_ip YOUR_TARGET_IP --scope CIDR_SCOP_IP --port PORT_RANGE_TO_TEST
```


<p>Once Finished with Running the Tool Deactivate the Virtual Environment</p>

```bash
deactivate
```

##  Team Members

<ul>
  <li><strong>Eric Bucher - Lead Developer</strong></li>
  <li><strong>Max Boon - Reconnaissance Agent Developer</strong></li>
  <li><strong>Will Gilkey - Vulnerability Analyst Agent Developer</strong></li>
  <li><strong>Connor Martin - Tester and Documentation Engineer</strong></li>
  <li><strong>Kris Kuusik - Report Writer Agent Developer</strong></li>
</ul>
