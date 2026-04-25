"""
Runs curl against the target IP and returns
the raw output as a string for LLM parsing
"""

import subprocess
from src.core.scope_guard import enforce_scope

def grab_http_headers(target_ip: str, port: str, scope: str) -> str:
    """
    Sends an HTTP HEAD request and returns the response headers.
    Used to fingerprint the web server and framework.
    Non-critical - curl failure does not stop the pipeline.
    """

    enforce_scope(target_ip, scope)
    target_url = f'http://{target_ip}:{port}'
    try:
        result = subprocess.run(
            ["curl", "-I", "-s", "--max-time", "10", "-L", "--insecure", target_url],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode != 0:
            print(f'curl on {target_url} returned non-zero exit code : {result.returncode}')
            return ''
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f'curl on {target_url} timed out after 15 seconds')
        return ''
    except FileNotFoundError:
        print('curl is not installed or not in PATH')
        return ''