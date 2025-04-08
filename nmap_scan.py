import subprocess
import re
import os
import sys
import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ANSI color codes
COLORS = {
    'HEADER': '\033[95m',
    'BLUE': '\033[94m',
    'CYAN': '\033[96m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'RED': '\033[91m',
    'BOLD': '\033[1m',
    'UNDERLINE': '\033[4m',
    'END': '\033[0m'
}

STATE_FILE = "nmap_scan_state.json"
ERROR_LOG_FILE = "nmap_scan_errors.log"


class ScanState:
    def __init__(self):
        self.target: str = ""
        self.open_ports: List[str] = []
        # List of (start_port, end_port) tuples
        self.scanned_ports: List[Tuple[int, int]] = []
        self.phase_completed: str = ""
        self.scan_type: str = ""
        self.timestamp: str = ""
        self.scan_command: List[str] = []
        self.scan_start_time: float = 0
        self.scan_end_time: float = 0
        self.error_count: int = 0
        self.last_error: str = ""
        self.progress: Dict[str, float] = {}  # Phase -> progress percentage

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "open_ports": self.open_ports,
            "scanned_ports": self.scanned_ports,
            "phase_completed": self.phase_completed,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "scan_command": self.scan_command,
            "scan_start_time": self.scan_start_time,
            "scan_end_time": self.scan_end_time,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "progress": self.progress
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ScanState':
        state = cls()
        state.target = data.get("target", "")
        state.open_ports = data.get("open_ports", [])
        state.scanned_ports = data.get("scanned_ports", [])
        state.phase_completed = data.get("phase_completed", "")
        state.scan_type = data.get("scan_type", "")
        state.timestamp = data.get("timestamp", "")
        state.scan_command = data.get("scan_command", [])
        state.scan_start_time = data.get("scan_start_time", 0)
        state.scan_end_time = data.get("scan_end_time", 0)
        state.error_count = data.get("error_count", 0)
        state.last_error = data.get("last_error", "")
        state.progress = data.get("progress", {})
        return state


def save_state(state: ScanState):
    """Save the current scan state to a file."""
    state.timestamp = datetime.now().isoformat()
    with open(STATE_FILE, 'w') as f:
        json.dump(state.to_dict(), f, indent=2)


def load_state() -> Optional[ScanState]:
    """Load the scan state from file if it exists."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                data = json.load(f)
                return ScanState.from_dict(data)
        except (json.JSONDecodeError, KeyError) as e:
            log_error(f"Error loading state file: {str(e)}")
            return None
    return None


def clear_state():
    """Clear the saved state file."""
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)


def print_header(text):
    """Print a formatted header with colors."""
    print(f"\n{COLORS['HEADER']}{'=' * 80}{COLORS['END']}")
    print(f"{COLORS['BOLD']}{COLORS['BLUE']}{text}{COLORS['END']}")
    print(f"{COLORS['HEADER']}{'=' * 80}{COLORS['END']}\n")


def print_success(text):
    """Print success message in green."""
    print(f"{COLORS['GREEN']}✅ {text}{COLORS['END']}")


def print_warning(text):
    """Print warning message in yellow."""
    print(f"{COLORS['YELLOW']}⚠️  {text}{COLORS['END']}")


def print_error(text):
    """Print error message in red."""
    print(f"{COLORS['RED']}❌ {text}{COLORS['END']}")


def print_info(text):
    """Print info message in cyan."""
    print(f"{COLORS['CYAN']}ℹ️  {text}{COLORS['END']}")


def log_error(error_msg: str):
    """Log an error message to the error log file."""
    timestamp = datetime.now().isoformat()
    with open(ERROR_LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {error_msg}\n")


def parse_xml_progress(xml_file: str) -> Tuple[List[str], List[Tuple[int, int]]]:
    """Parse Nmap XML output to get open ports and scanned ranges."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        open_ports = []
        scanned_ranges = []

        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                if port.find('state').get('state') == 'open':
                    port_id = port.get('portid')
                    open_ports.append(port_id)

            for port_range in host.findall('.//portused'):
                start = int(port_range.get('start'))
                end = int(port_range.get('end'))
                scanned_ranges.append((start, end))

        return open_ports, scanned_ranges
    except ET.ParseError as e:
        log_error(f"Error parsing XML file: {str(e)}")
        return [], []


def run_nmap_command(command: List[str], state: ScanState) -> Tuple[bool, str]:
    """Run Nmap command and capture output with progress tracking."""
    try:
        state.scan_start_time = time.time()
        state.scan_command = command
        print_info(
            f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        output = []
        last_progress_update = time.time()

        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                print(line.strip())
                output.append(line)

                # Update progress every 5 seconds
                current_time = time.time()
                if current_time - last_progress_update >= 5:
                    # Try to extract progress from Nmap output
                    progress_match = re.search(r'(\d+\.\d+)% done', line)
                    if progress_match:
                        progress = float(progress_match.group(1))
                        state.progress[state.phase_completed] = progress
                        save_state(state)
                        last_progress_update = current_time

        state.scan_end_time = time.time()
        return True, ''.join(output)
    except subprocess.CalledProcessError as e:
        error_msg = f"Error executing command: {e}"
        log_error(error_msg)
        state.error_count += 1
        state.last_error = error_msg
        save_state(state)
        return False, error_msg
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user. Progress has been saved.")
        return False, "Interrupted by user"


def get_open_ports(target: str, state: ScanState) -> Optional[str]:
    """Scan ports for open status and return the open ports."""
    print_header("🔍 PORT SCAN PHASE")
    print_info("Scanning ports for open status...")

    # Check if we can resume from previous scan
    resume_file = "nmap-open-ports.xml"
    if os.path.exists(resume_file) and state.scanned_ports:
        print_info("Resuming previous port scan...")
        command = ["sudo", "nmap", "--resume", resume_file, target]
    else:
        command = ["sudo", "nmap", "-p-", "--open", "-T4",
                   "-Pn", "--stats-every", "15s", "-oX", resume_file, target]

    state.phase_completed = "port_scan"
    success, output = run_nmap_command(command, state)

    if not success:
        if output == "Interrupted by user":
            save_state(state)
        return None

    # Parse results from XML
    open_ports, scanned_ranges = parse_xml_progress(resume_file)
    state.open_ports = open_ports
    state.scanned_ports = scanned_ranges

    if open_ports:
        print_success(f"Open ports found: {', '.join(open_ports)}")
        save_state(state)
        return ",".join(open_ports)
    else:
        print_warning("No open ports found.")
        return None


def scan_open_ports(target: str, open_ports: str, state: ScanState) -> bool:
    """Run a detailed scan on the open ports."""
    if not open_ports:
        print_error("No open ports provided for detailed scan")
        return False

    print_header("🔬 DETAILED SCAN PHASE")
    print_info(
        f"Scanning open ports ({open_ports}) for services, OS, and vulnerabilities...")

    command = ["sudo", "nmap", "-sV", "-O", "-sC",
               "--script=vuln,http-enum,smb-enum-shares,dns-zone-transfer",
               "-p", open_ports, "--stats-every", "15s",
               "-oA", "nmap-detailed-scan", target]

    state.phase_completed = "detailed_scan"
    success, output = run_nmap_command(command, state)

    if not success:
        if output == "Interrupted by user":
            save_state(state)
        return False

    print_success("Scan complete. Results saved in nmap-*.xml files")
    state.phase_completed = "complete"
    save_state(state)
    return True


def is_resumable_state(state: ScanState) -> bool:
    """Check if the state is in a resumable condition."""
    if not state:
        return False

    valid_phases = ["port_scan", "detailed_scan"]
    if state.phase_completed not in valid_phases:
        return False

    # For port_scan phase, we can resume if we have scanned ports
    if state.phase_completed == "port_scan" and state.scanned_ports:
        return True

    # For detailed_scan phase, we need open ports
    if state.phase_completed == "detailed_scan" and state.open_ports:
        return True

    return False


def main():
    """Main function to orchestrate the scan process."""
    print_header("🚀 NMAP SCAN SCRIPT")

    # Initialize or load state
    state = load_state() or ScanState()

    if state.target:
        print_info("Found previous scan state:")
        print_info(f"Target: {state.target}")
        print_info(f"Last phase: {state.phase_completed}")
        if state.open_ports:
            print_info(f"Open ports found: {', '.join(state.open_ports)}")
        if state.scanned_ports:
            print_info(f"Scanned port ranges: {state.scanned_ports}")
        print_info(
            f"Progress: {state.progress.get(state.phase_completed, 0)}%")
        print_info(f"Timestamp: {state.timestamp}")

        if is_resumable_state(state):
            resume = input(
                f"{COLORS['CYAN']}Do you want to resume the previous scan? (y/n): {COLORS['END']}").strip().lower()
            if resume == 'y':
                target = state.target
                if state.phase_completed == "port_scan":
                    print_info("Resuming port scan...")
                    open_ports = get_open_ports(target, state)
                    if open_ports:
                        scan_open_ports(target, open_ports, state)
                elif state.phase_completed == "detailed_scan":
                    print_info("Resuming detailed scan...")
                    scan_open_ports(target, ",".join(state.open_ports), state)
            else:
                clear_state()
                target = input(
                    f"{COLORS['CYAN']}Enter target IP address (e.g., 192.168.1.1): {COLORS['END']}").strip()
        else:
            print_warning(
                "Previous scan was not in a resumable state. Starting new scan.")
            clear_state()
            target = input(
                f"{COLORS['CYAN']}Enter target IP address (e.g., 192.168.1.1): {COLORS['END']}").strip()
    else:
        print_info(
            "This script will perform a comprehensive network scan in two phases:")
        print_info("1. Initial port scan to identify open ports")
        print_info(
            "2. Detailed scan of open ports for services, OS, and vulnerabilities")
        target = input(
            f"{COLORS['CYAN']}Enter target IP address (e.g., 192.168.1.1): {COLORS['END']}").strip()

    if not target:
        print_error("Invalid target. Exiting.")
        return

    state.target = target
    save_state(state)

    # Step 1: Scan open ports
    open_ports = get_open_ports(target, state)
    if open_ports is None:
        return

    # Step 2: Scan the identified open ports for services and OS
    if not scan_open_ports(target, open_ports, state):
        return

    print_header("✨ SCAN COMPLETE")
    print_success("All scan phases completed successfully!")
    print_info("Check the nmap-*.xml files for detailed results.")
    clear_state()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nScript interrupted by user. Progress has been saved.")
        sys.exit(0)
