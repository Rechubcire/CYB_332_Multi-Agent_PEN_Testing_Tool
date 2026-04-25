"""
Runs gobuster against the target IP and returns
the raw output as a string for LLM parsing
"""

import subprocess, os
from src.core.scope_guard import enforce_scope

def run_gobuster(target_ip: str, port: str, scope: str) -> str:
    """
    Runs gobuster brute force scan against the target directory.
    Returns raw gobuster output as a string
    """

    enforce_scope(target_ip, scope)
    target_url = f'http://{target_ip}:{port}'
    wordlist = os.getenv('WORDLIST_PATH', '/usr/share/wordlists/dirb/common.txt')
    if not os.path.exists(wordlist):
        print(f'Wordlist not found at {wordlist} - skipping gobuster on port {port}')
        return ''
    try:
        result = subprocess.run(
            ["gobuster", "dir", "-u", target_url, "-w", wordlist, "-q", "-t", "20", "--no-error"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            print(f'gobuster on {target_url} returned non-zero exit code : {result.returncode}')
            return ''
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f'gobuster on {target_url} timed out after 120 seconds')
        if result.stdout:
            return result.stdout
        else:
            return ''
    except FileNotFoundError:
        print('gobuster is not installed or not in PATH')
        return ''