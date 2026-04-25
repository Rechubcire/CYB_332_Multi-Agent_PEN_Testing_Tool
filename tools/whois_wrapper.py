"""
Runs whois against the target IP and returns
the raw output as a string for LLM parsing
"""

import subprocess

def run_whois(target_ip: str) -> str:
    """
    Runs whois against the target IP address.
    Returns raw whois output as a string.
    """
    try:
        result = subprocess.run(
            ["whois",target_ip],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            print(f'whois returned non-zero exit code : {result.returncode}')
            return ''
        return result.stdout
    except subprocess.TimeoutExpired:
        print('whois timed out after 30 seconds')
        return ''
    except FileNotFoundError:
        print('whois is not installed or not in PATH')
        return ''