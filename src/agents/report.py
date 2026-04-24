import json
import logging
from typing import Any

from src.core.llm_client import call_llm, load_prompt
from src.core.state import PentestState, log_event, log_error

# Module-level logger — entries appear in output/run.log via the root handler
logger = logging.getLogger(__name__)


# Public node function — registered in build_graph() as 'report_writer'

def report_agent(state: PentestState) -> dict:
    """
    LangGraph node function — Node 4 of 4.

    Receives:
        state['vulnerabilities'] — list written by vuln_node (Node 3)
        state['recon']           — dict written by recon_node (Node 2)
        state meta fields        — target_ip, scope, allowed_ports, session_id, timestamp

    Returns:
        Partial state dict that LangGraph merges automatically:
        {
            'report':  <structured report dict>,
            'status':  'complete',
            'logs':    <updated log list>
        }

    On failure returns:
        {
            'status': 'failed',
            'errors': <updated error list>
        }
    """
    vulns = state.get("vulnerabilities", [])
    recon = state.get("recon", {})

    # ── Log the start of this node
    log_update = log_event(
        state,
        "report_writer",
        f"Writing report for {len(vulns)} finding(s) against {state['target_ip']}",
    )

    # Pre-compute risk matrix so the LLM does not have to count
    risk_counts = _count_severities(vulns)
    overall_risk = _determine_overall_risk(risk_counts)

    logger.info(
        "report_writer | risk_matrix=%s | overall_risk=%s",
        risk_counts,
        overall_risk,
    )

    # Pull safe defaults from recon (fields may be absent if recon failed)
    scan_time = recon.get("scan_time") or state.get("timestamp", "unknown")
    os_guess  = (recon.get("os_detection") or {}).get("guess", "unknown")
    web_paths = recon.get("web_paths", [])

    # Build the LLM user prompt
    user_content = (
        "Write a complete, professional penetration test report\n"
        "based on the data below. Follow the report schema in your system prompt.\n\n"
        f"TARGET SCOPE:   {state['scope']}\n"
        f"SCAN DATE:      {scan_time}\n"
        f"ALLOWED PORTS:  {state['allowed_ports']}\n"
        f"OVERALL RISK:   {overall_risk}\n\n"
        "VULNERABILITIES FOUND:\n"
        + json.dumps(vulns, indent=2)
        + "\n\nOPEN PORTS SUMMARY:\n"
        + json.dumps(recon.get("open_ports", []), indent=2)
        + f"\n\nOS DETECTED: {os_guess}"
        + "\n\nRISK MATRIX: "
        + json.dumps(risk_counts)
        + "\n\nWEB PATHS FOUND: "
        + str(web_paths)
        + "\n\nReturn ONLY the report JSON object. No markdown. No explanation."
    )

    # Load the system prompt from prompts/report_writer_system.txt
    try:
        system_prompt = load_prompt("report_writer_system.txt")
    except FileNotFoundError as exc:
        err = f"report_writer | system prompt not found: {exc}"
        logger.error(err)
        error_update = log_error(state, "report_writer", err)
        return {**log_update, **error_update, "status": "failed"}

    # Call the LLM with retry logic (max 3 attempts)
    try:
        report_data = _call_llm_with_retry(
            system_prompt=system_prompt,
            user_content=user_content,
            agent_name="report_writer",
            max_tokens=4000,   # report nodes need more tokens than other agents
            max_attempts=3,
        )
    except RuntimeError as exc:
        err = f"report_writer | LLM failed after retries: {exc}"
        logger.error(err)
        error_update = log_error(state, "report_writer", err)
        return {**log_update, **error_update, "status": "failed"}

    # Validate the top-level response shape
    if not isinstance(report_data, dict):
        err = (
            f"report_writer | LLM returned {type(report_data).__name__}, expected dict."
        )
        logger.error(err)
        error_update = log_error(state, "report_writer", err)
        return {**log_update, **error_update, "status": "failed"}

    # Enforce computed values — do NOT trust the LLM's own counts
    report_data["risk_matrix"]        = risk_counts
    report_data["risk_rating_overall"] = overall_risk

    # Append raw tool outputs for the report appendix
    # The system prompt instructs the LLM to leave 'raw_tool_outputs' as '',
    # and the Python node fills it in here so we control formatting exactly.
    report_data["raw_tool_outputs"] = _build_raw_appendix(recon)

    # Ensure all required fields exist (default to empty string if absent)
    _apply_required_defaults(report_data)

    logger.info("report_writer | report JSON assembled successfully")

    # Return partial state update — LangGraph merges automatically
    return {
        **log_update,
        "report": report_data,
        "status": "complete",
    }


# Private helpers

def _call_llm_with_retry(
    system_prompt: str,
    user_content: str,
    agent_name: str,
    max_tokens: int = 4000,
    max_attempts: int = 3,
) -> Any:
    """
    Wraps call_llm() with retry logic.

    If the LLM returns malformed JSON, a corrective message is appended to the
    user content and the call is retried.  After max_attempts failures a
    RuntimeError is raised so report_node() can log and return a failed state.

    Args:
        system_prompt: The system-role prompt loaded from prompts/
        user_content:  The user-role message containing all recon + vuln data
        agent_name:    Label used for run.log entries
        max_tokens:    Override passed through to call_llm(); report node needs 4000
        max_attempts:  Number of retry attempts before giving up

    Returns:
        Parsed Python object (dict expected by report_node)

    Raises:
        RuntimeError: If all attempts fail
    """
    corrective_suffix = ""

    for attempt in range(1, max_attempts + 1):
        try:
            result = call_llm(
                system_prompt=system_prompt,
                user_content=user_content + corrective_suffix,
                max_tokens=max_tokens,
                agent_name=agent_name,
            )
            return result  # success — exit immediately

        except json.JSONDecodeError as exc:
            logger.warning(
                "report_writer | attempt %d/%d failed — JSON decode error: %s",
                attempt,
                max_attempts,
                exc,
            )
            if attempt == max_attempts:
                raise RuntimeError(
                    f"{agent_name} failed after {max_attempts} attempts. "
                    f"Last JSON error: {exc}"
                ) from exc

            # Build a corrective prompt to append on the next attempt
            corrective_suffix = (
                "\n\n--- CORRECTION REQUIRED ---\n"
                "Your previous response could not be parsed as valid JSON.\n"
                f"The error was: {exc}\n"
                "Return ONLY valid JSON. No markdown. No explanation. "
                "No code fences. No text before or after the JSON object.\n"
                "--- END CORRECTION ---"
            )


def _count_severities(vuln_list: list) -> dict:
    """
    Counts how many vulnerabilities fall into each severity bucket.

    Args:
        vuln_list: List of vulnerability dicts from state['vulnerabilities']

    Returns:
        Dict with keys Critical, High, Medium, Low, Info and integer counts
    """
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for vuln in vuln_list:
        severity = vuln.get("severity", "Info")
        if severity in counts:
            counts[severity] += 1
        else:
            # Unknown severity — treat conservatively as Info
            counts["Info"] += 1
    return counts


def _determine_overall_risk(risk_counts: dict) -> str:
    """
    Returns the highest severity that has at least one finding.

    Walk from most severe to least severe so the first non-zero bucket wins.
    Falls back to 'Info' if no findings exist at all.

    Args:
        risk_counts: Output of _count_severities()

    Returns:
        One of: 'Critical', 'High', 'Medium', 'Low', 'Info'
    """
    for level in ["Critical", "High", "Medium", "Low"]:
        if risk_counts.get(level, 0) > 0:
            return level
    return "Info"


def _build_raw_appendix(recon: dict) -> str:
    """
    Concatenates the raw tool outputs for the appendix section of the report.

    The LLM is instructed to leave 'raw_tool_outputs' as an empty string.
    This function fills it in after the LLM call so formatting is always
    consistent regardless of what the model produces.

    Args:
        recon: state['recon'] dict populated by recon_node

    Returns:
        Multi-section string with labelled raw output blocks
    """
    nmap_raw  = recon.get("nmap_raw",  "(nmap output not available)")
    whois_raw = recon.get("whois_raw", "(whois output not available)")
    web_paths = recon.get("web_paths", [])

    web_paths_str = (
        "\n".join(str(p) for p in web_paths)
        if web_paths
        else "(no web paths discovered)"
    )

    return (
        "=== NMAP XML OUTPUT ===\n"
        + nmap_raw
        + "\n\n=== WEB PATHS DISCOVERED ===\n"
        + web_paths_str
        + "\n\n=== WHOIS OUTPUT ===\n"
        + whois_raw
    )


def _apply_required_defaults(report_data: dict) -> None:
    """
    Ensures every key the report schema requires is present in report_data.

    Applied after the LLM call so downstream code (save_report_to_disk,
    the presentation layer) never hits a KeyError even if the LLM omitted
    an optional section.

    Mutates report_data in place — does NOT overwrite values already present.

    Required top-level keys and their safe defaults:
        executive_summary      → ""
        scope_and_methodology  → ""
        risk_rating_overall    → "Info"
        findings               → []
        risk_matrix            → {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
        raw_tool_outputs       → ""
    """
    defaults: dict = {
        "executive_summary":     "",
        "scope_and_methodology": "",
        "risk_rating_overall":   "Info",
        "findings":              [],
        "risk_matrix":           {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
        },
        "raw_tool_outputs":      "",
    }
    for key, default_value in defaults.items():
        report_data.setdefault(key, default_value)

    # Validate findings list shape — each finding must have required sub-keys
    validated_findings = []
    finding_defaults = {
        "vuln_id":     None,
        "title":       "Untitled Finding",
        "severity":    "Info",
        "evidence":    "",
        "cve":         None,
        "remediation": "",
    }
    for finding in report_data.get("findings", []):
        if isinstance(finding, dict):
            for fkey, fval in finding_defaults.items():
                finding.setdefault(fkey, fval)
            validated_findings.append(finding)

    report_data["findings"] = validated_findings