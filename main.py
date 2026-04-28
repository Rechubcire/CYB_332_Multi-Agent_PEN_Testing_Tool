"""
This it the entry point for all test. Here
you will use the CLI to interact with the tool
"""
from dotenv import load_dotenv
import os
import sys
import argparse
import ipaddress
from src.agents.orchestrator import build_graph
from src.core.state import initialise_state, save_state_to_disk, save_report_to_disk
from src.core.scope_guard import ScopeViolationError

def is_valid_ip(target_ip: str) -> bool:
    """
    Checks to see if the user entered a
    valid IP address
    """
    try:
        ipaddress.ip_address(target_ip)
        return True
    except ValueError:
        return False
    
def is_valid_cidr(scope: str) -> bool:
    """
    Checks to see if the user entered a
    valid address in CIDR notation
    """
    try:
        ipaddress.ip_network(scope)
        return True
    except ValueError:
        return False
    
def validate_port_list(ports: str) -> list:
    """
    Takes a string with ports and makes a 
    list of the port range
    """
    try:
        # Split the port range str at the '-'
        port_range = ports.split("-")
        
        # Only one port was allowed
        if len(port_range) == 1:
            port = int(port_range[0])
            
            # Make sure that the given port is within range
            if port >= 1 and port <= 65535:
                return port_range
            else:
                return []
        
        # Given a range of ports
        elif len(port_range) == 2:
            start = int(port_range[0])
            end = int(port_range[1])
            
            # Make sure that the given range is valid
            if (1 <= start <= 65535) and (1 <= end <= 65535) and (start <= end):
                return port_range
            else:
                return []
        else:
            return False
    except ValueError:
        return []

    
def main():
    # Load the .env file
    load_dotenv()

    # Define the CLI command and its arguments
    parser = argparse.ArgumentParser(description='CYB332 Multi-Agent LLM Penetration Testing Tool')

    # Command looks like: python main.py --target_ip 192.168.56.101 --scope 192.168.56.101/32 --port 1-2000
    # Make sure you are in the folder that contains main.py
    parser.add_argument('--target_ip', required=True, help='Target VM IPv4 Address')
    parser.add_argument('--scope', required=True, help='Allowed CIDR scope')
    parser.add_argument('--port', required=False, default='1-1024', help='Target ports allowed in scope')

    args = parser.parse_args()

    # Input validation
    print("Verifying input")

    # Verify the target_ip address
    if not is_valid_ip(args.target_ip):
        print(f"Error: The provided value of {args.target_ip} for '--target_ip' is invalid. Must be a valid IP address e.g.'192.168.56.101'")
        sys.exit(1)

    # Verify the scope address in CIDR notation
    if not is_valid_cidr(args.scope):
        print(f"Error: The provided value of {args.scope} for '--scope' is invalid. Must be a CIDR string e.g.'192.168.56.101/32'")
        sys.exit(1)

    # Verify port range and make a list for the ends of the range
    port_list = validate_port_list(args.port)
    if len(port_list) == 0:
        print(f"Error: The provided value of {args.port} for '--port' is invalid. Must be a port or port range e.g.'80' or '1-65535'")
        sys.exit(1)

    print("Input verified. Initializing state and building the pipeline.\n")

     # Create initial state from user input and build graph
    initial_state = initialise_state(args.target_ip, args.scope, args.port)
    graph = build_graph()

    try:
        print("Running\n")
        # invoke the graph with the initial state to start the pipeline
        final_state = graph.invoke(initial_state)

        
        # Save the state and to the disk Report will also be on disk 
        # but that is handled by the report writer agent (agent 4)
        print("Saving files\n")
        save_state_to_disk(final_state)
        save_report_to_disk(final_state.get('report'))

        print("Pipeline complete\n")
        sys.exit(0)

    except ScopeViolationError as e:
        print(f"Error: Scope Violation. Halting. {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Run interrupted by user, Halting.")
        sys.exit(1)

    except Exception as e:
        print(f"Unexpected Error: {type(e).__name__}: {e}")
        print("Check output/run.log for detailed error information")
        sys.exit(1)


if __name__ == "__main__":
    main()
