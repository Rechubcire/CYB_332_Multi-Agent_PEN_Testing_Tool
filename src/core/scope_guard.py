"""
 Scope validation file. Called before any tool or agent is
 called. This ensures that the agent/tool in use is in the
 correct scope. This is the most important safety file.
"""

import ipaddress

class ScopeViolationError(Exception):
    """
    Custom exception class that is raised by
    enforce_scope() whenever an IP address falls
    out of the given scope
    """

    pass

def is_in_scope(target_ip: str, scope_cidr: str) -> bool:
    """
    Given a target IP and scope CIDR. Make sure
    that the target IP is in the scope CIDR
    """

    try:
        network = ipaddress.ip_network(scope_cidr, strict=False)
        address = ipaddress.ip_address(target_ip)

        # Check to see if the address is in network
        return (address in network)
    except ValueError:

        # Invalid input
        return False
    
def enforce_scope(target_ip: str, scope_cidr: str) -> None:
    """
    Make sure that the target IP address is in
    scope, and enforce the given scope. If not
    in scope then raise the ScopeViolationError
    exception
    """
    if is_in_scope(target_ip, scope_cidr):
        raise ScopeViolationError(
            f"Scope Violation Error: {target_ip} is not included in the given scope {scope_cidr}.")
    
    # If exception is not raise then the 
    # given address is in scope

def validate_port_range(port_range: str) -> bool:
    """
    Validate the given port range and make sure
    that they are in range of the available ports
    """

    try:
        # Split the port range str at the '-'
        ends = port_range.split("-")
        
        # Only one port was allowed
        if len(ends) == 1:
            port = int(ends[0])
            return port >= 1 and port <= 65535
        
        # Given a range of ports
        elif len(ends) == 2:
            start = int(ends[0])
            end = int(ends[1])
            return (1 <= start <= 65535) and (1 <= end <= 65535) and (start <= end)
        else:
            return False
    except ValueError:
        return False

