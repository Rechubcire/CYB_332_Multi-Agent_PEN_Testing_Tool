"""
Runs nmap against the target IP and returns
the raw output as a string for LLM parsing
"""

import subprocess
from src.core.scope_guard import enforce_scope

def run_nmap(target_ip: str, port_range: str, scope: str) -> str:
    """
    Runs nmap scan against target.
    Returns raw nmap output as a string.
    """
    enforce_scope(target_ip, scope)

    try:
        result = subprocess.run(
            ["nmap", "-sV", "-O", "-sC", "--open", "-p", port_range, "-oX", "-", target_ip],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode >= 2:
            raise RuntimeError(f"nmap failed with code {result.returncode}: {result.stderr[:300]}")
        if not result.stdout:
            raise RuntimeError("nmap produced no output")
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError("nmap timed out after 300 seconds")
    except FileNotFoundError:
        raise RuntimeError("nmap is not installed or not in PATH")
