"""
Runs nmap against the target IP and returns
the raw output as a string for LLM parsing
"""

import subprocess

def run_nmap(target_ip: str, ports: str = "1-65535") -> str:
    """
    Runs nmap service/version scan against target.
    Returns raw nmap output as a string.
    """
    try:
        result = subprocess.run(["nmap", "-sV", "-sC", "--open", "-p", ports, target_ip], 
                                capture_output=True,
                                text=True,
                                timeout=120)
        if result.stdout:
            return result.stdout
        else:
            return result.stderr
    except subprocess.TimeoutExpired:
        return "ERROR: nmap scan timed out"
    except FileNotFoundError:
        return "ERROR: nmap is not installed or not in PATH"
    except Exception as e:
        return f"ERROR: {str(e)}"
