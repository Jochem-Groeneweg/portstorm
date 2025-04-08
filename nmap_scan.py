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
        self.open_udp_ports: List[str] = []  # New field for UDP ports
        # List of (start_port, end_port) tuples
        self.scanned_ports: List[Tuple[int, int]] = []
        # New field for UDP port ranges
        self.scanned_udp_ports: List[Tuple[int, int]] = []
        self.phase_completed: str = ""
        self.scan_type: str = ""
        self.scan_mode: str = "stealth"  # New field: stealth or aggressive
        self.scan_udp: bool = False  # New field: whether to scan UDP ports
        self.scan_timing: str = "normal"  # New field: normal, slow, or fast
        self.use_evasion: bool = False  # New field: whether to use evasion techniques
        self.cloud_aware: bool = False  # New field: whether to use cloud-aware scanning
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
            "open_udp_ports": self.open_udp_ports,
            "scanned_ports": self.scanned_ports,
            "scanned_udp_ports": self.scanned_udp_ports,
            "phase_completed": self.phase_completed,
            "scan_type": self.scan_type,
            "scan_mode": self.scan_mode,
            "scan_udp": self.scan_udp,
            "scan_timing": self.scan_timing,
            "use_evasion": self.use_evasion,
            "cloud_aware": self.cloud_aware,
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
        state.open_udp_ports = data.get("open_udp_ports", [])
        state.scanned_ports = data.get("scanned_ports", [])
        state.scanned_udp_ports = data.get("scanned_udp_ports", [])
        state.phase_completed = data.get("phase_completed", "")
        state.scan_type = data.get("scan_type", "")
        state.scan_mode = data.get("scan_mode", "stealth")
        state.scan_udp = data.get("scan_udp", False)
        state.scan_timing = data.get("scan_timing", "normal")
        state.use_evasion = data.get("use_evasion", False)
        state.cloud_aware = data.get("cloud_aware", False)
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


def run_nmap_command(command: List[str], state: ScanState):
    """Run Nmap command and capture output with progress tracking."""
    try:
        state.scan_start_time = time.time()
        state.scan_command = command
        print_info(
            f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Run the command and capture output in real-time
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Combine stderr with stdout
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        output = []
        last_progress = 0
        current_task = "Initializing scan..."

        # Clear the current line
        print("\033[K", end="\r")

        while True:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue

            output.append(line)

            # Extract progress and task information
            progress_match = re.search(r'About (\d+\.\d+)% done', line)
            task_match = re.search(r'undergoing (.*?) Scan', line)

            if progress_match:
                progress = float(progress_match.group(1))
                if progress != last_progress:
                    last_progress = progress
                    # Clear the current line and show progress
                    print("\033[K", end="\r")
                    print(
                        f"{COLORS['CYAN']}Progress: {progress:.1f}% | Task: {current_task}{COLORS['END']}", end="\r")
                    sys.stdout.flush()  # Force flush the output

            if task_match:
                current_task = task_match.group(1)
                # Clear the current line and show new task
                print("\033[K", end="\r")
                print(
                    f"{COLORS['CYAN']}Progress: {last_progress:.1f}% | Task: {current_task}{COLORS['END']}", end="\r")
                sys.stdout.flush()  # Force flush the output

        # Wait for the process to complete and get the return code
        return_code = process.wait()

        # Clear the final progress line
        print("\033[K", end="\r")

        # Check if the process completed successfully
        if return_code == 0:
            print_success("Scan completed successfully!")
            state.scan_end_time = time.time()
            return True, ''.join(output)
        else:
            error_msg = f"Scan failed with return code {return_code}"
            print_error(error_msg)
            state.scan_end_time = time.time()
            return False, error_msg

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


def scan_udp_ports(target: str, state: ScanState) -> Optional[str]:
    """Scan UDP ports and return the open ports."""
    print_header("🔍 UDP PORT SCAN PHASE")
    print_info("Scanning UDP ports...")

    resume_file = "nmap-udp-ports.xml"
    if os.path.exists(resume_file) and state.scanned_udp_ports:
        print_info("Resuming previous UDP port scan...")
        command = ["nmap", "--resume", resume_file, target]
    else:
        command = ["nmap", "-sU", "--top-ports", "1000", "--open", "-Pn", "-T4",
                   "--stats-every", "5s", "-oX", resume_file, target]

    state.phase_completed = "udp_port_scan"
    success, output = run_nmap_command(command, state)

    if not success:
        if output == "Interrupted by user":
            save_state(state)
        return None

    # Wait a moment to ensure the file is written
    time.sleep(1)

    # Parse results from XML
    if os.path.exists(resume_file):
        open_ports, scanned_ranges = parse_xml_progress(resume_file)
        state.open_udp_ports = open_ports
        state.scanned_udp_ports = scanned_ranges

        if open_ports:
            print_success(f"Open UDP ports found: {', '.join(open_ports)}")
            save_state(state)
            return ",".join(open_ports)
        else:
            print_warning("No open UDP ports found.")
            return None
    else:
        print_error(
            f"Failed to create scan results file. Command output: {output}")
        return None


def scan_tcp_ports(target: str, state: ScanState) -> Optional[str]:
    """Scan TCP ports and return the open ports."""
    print_header("🔍 TCP PORT SCAN PHASE")
    print_info("Scanning TCP ports...")

    # Check if we can resume from previous scan
    resume_file = "nmap-tcp-ports.xml"
    if os.path.exists(resume_file) and state.scanned_ports:
        print_info("Resuming previous TCP port scan...")
        command = ["nmap", "--resume", resume_file, target]
    else:
        command = ["nmap", "-p-", "--open", "-T4", "-Pn",
                   "--stats-every", "5s", "-oX", resume_file, target]

    state.phase_completed = "tcp_port_scan"
    success, output = run_nmap_command(command, state)

    if not success:
        if output == "Interrupted by user":
            save_state(state)
        return None

    # Wait a moment to ensure the file is written
    time.sleep(1)

    # Parse results from XML
    if os.path.exists(resume_file):
        open_ports, scanned_ranges = parse_xml_progress(resume_file)
        state.open_ports = open_ports
        state.scanned_ports = scanned_ranges

        if open_ports:
            print_success(f"Open TCP ports found: {', '.join(open_ports)}")
            save_state(state)
            return ",".join(open_ports)
        else:
            print_warning("No open TCP ports found.")
            return None
    else:
        print_error(
            f"Failed to create scan results file. Command output: {output}")
        return None


def is_resumable_state(state: ScanState):
    """Check if the state is in a resumable condition."""
    if not state or not state.target:
        return False

    # Check if we have the necessary files for the current phase
    if state.phase_completed == "port_scan":
        return os.path.exists("nmap-tcp-ports.xml")
    elif state.phase_completed == "udp_port_scan":
        return os.path.exists("nmap-udp-ports.xml")
    elif state.phase_completed in ["comprehensive_scan_tcp", "comprehensive_scan_udp"]:
        # For comprehensive scans, we can resume if we have the port scan results
        return (os.path.exists("nmap-tcp-ports.xml") or
                os.path.exists("nmap-udp-ports.xml"))
    return False


def main():
    """Main function to orchestrate the scan process."""
    print_header("🚀 NMAP SCAN SCRIPT")

    # Check if nmap is installed
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error(
            "Nmap is not installed or not in PATH. Please install nmap first.")
        return

    # Initialize or load state
    state = load_state() or ScanState()

    if state.target:
        print_info("Found previous scan state:")
        print_info(f"Target: {state.target}")
        print_info(f"Last phase: {state.phase_completed}")
        if state.open_ports:
            print_info(f"Open TCP ports found: {', '.join(state.open_ports)}")
        if state.open_udp_ports:
            print_info(
                f"Open UDP ports found: {', '.join(state.open_udp_ports)}")
        if state.scanned_ports:
            print_info(f"Scanned port ranges: {state.scanned_ports}")
        print_info(f"Timestamp: {state.timestamp}")

        if is_resumable_state(state):
            resume = input(
                f"{COLORS['CYAN']}Do you want to resume the previous scan? (y/n): {COLORS['END']}").strip().lower()
            if resume == 'y':
                target = state.target
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
        print_info("1. Full port scan to identify all open ports")
        print_info("2. Detailed service and vulnerability scan on open ports")

        target = input(
            f"{COLORS['CYAN']}Enter target IP address (e.g., 192.168.1.1): {COLORS['END']}").strip()

    if not target:
        print_error("Invalid target. Exiting.")
        return

    # If target changed, clear the state
    if state.target and state.target != target:
        print_warning("Target changed. Starting new scan.")
        clear_state()
        state = ScanState()

    # Select scan type
    print_header("🔍 SCAN TYPE SELECTION")
    print_info("Choose which type of scan to perform:")
    print_info("1. TCP ports only")
    print_info("2. UDP ports only")
    print_info("3. Both TCP and UDP ports")

    scan_type = input(
        f"{COLORS['CYAN']}Enter your choice (1-3) [3]: {COLORS['END']}").strip()

    if scan_type not in ["1", "2", "3"]:
        scan_type = "3"  # Default to both if invalid input

    scan_tcp = scan_type in ["1", "3"]
    scan_udp = scan_type in ["2", "3"]

    state.target = target
    save_state(state)

    # Step 1: Full TCP port scan
    if scan_tcp and (not state.phase_completed or state.phase_completed == "tcp_port_scan"):
        print_header("🔍 FULL TCP PORT SCAN")
        print_info("Scanning all 65535 TCP ports...")
        open_ports = scan_tcp_ports(target, state)
        if not open_ports:
            print_warning("No open TCP ports found.")
    else:
        open_ports = ",".join(state.open_ports) if state.open_ports else None

    # Step 2: Full UDP port scan
    if scan_udp and (not state.phase_completed or state.phase_completed in ["tcp_port_scan", "udp_port_scan"]):
        print_header("🔍 FULL UDP PORT SCAN")
        print_info("Scanning all 65535 UDP ports...")
        open_udp_ports = scan_udp_ports(target, state)
        if not open_udp_ports:
            print_warning("No open UDP ports found.")
    else:
        open_udp_ports = ",".join(
            state.open_udp_ports) if state.open_udp_ports else None

    # Step 3: Comprehensive scan on all open ports
    if (scan_tcp and open_ports) or (scan_udp and open_udp_ports):
        print_header("🔬 COMPREHENSIVE SCAN")
        print_info(
            "Performing detailed service and vulnerability scan on open ports...")

        tcp_success = False
        udp_success = False

        # Run comprehensive scan for TCP ports
        if scan_tcp and open_ports and (not state.phase_completed or
                                        state.phase_completed in ["tcp_port_scan", "udp_port_scan", "comprehensive_scan_tcp"]):
            print_info("Scanning TCP ports...")
            # Check if we're on Windows
            if os.name == 'nt':
                tcp_command = [
                    "nmap", "-sV", "-O", "-sC", "-T4", "-Pn",
                    "--script=vulners,http-enum,smb-enum-shares,ftp-anon",
                    "--version-all", "--traceroute",
                    "--stats-every", "5s",
                    "-oA", "nmap-tcp-comprehensive",
                    "-p", open_ports, target
                ]
            else:
                tcp_command = [
                    "sudo", "nmap", "-sV", "-O", "-sC", "-T4", "-Pn",
                    "--script=vulners,http-enum,smb-enum-shares,ftp-anon",
                    "--version-all", "--traceroute",
                    "--stats-every", "5s",
                    "-oA", "nmap-tcp-comprehensive",
                    "-p", open_ports, target
                ]
            state.phase_completed = "comprehensive_scan_tcp"
            tcp_success, output = run_nmap_command(tcp_command, state)
            if not tcp_success:
                print_warning(
                    "TCP comprehensive scan was not completed successfully")
            else:
                print_success(
                    "TCP comprehensive scan results saved in nmap-tcp-comprehensive.* files")

        # Run comprehensive scan for UDP ports
        if scan_udp and open_udp_ports and (not state.phase_completed or
                                            state.phase_completed in ["tcp_port_scan", "udp_port_scan", "comprehensive_scan_udp"]):
            print_info("Scanning UDP ports...")
            # Check if we're on Windows
            if os.name == 'nt':
                udp_command = [
                    "nmap", "-sU", "-sV", "-O", "-sC", "-T4", "-Pn",
                    "--script=dns-nsid,ntp-monlist,snmp-info,dhcp-discover,tftp-enum",
                    "--version-all",
                    "--stats-every", "5s",
                    "-oA", "nmap-udp-comprehensive",
                    "-p", open_udp_ports, target
                ]
            else:
                udp_command = [
                    "sudo", "nmap", "-sU", "-sV", "-O", "-sC", "-T4", "-Pn",
                    "--script=dns-nsid,ntp-monlist,snmp-info,dhcp-discover,tftp-enum",
                    "--version-all",
                    "--stats-every", "5s",
                    "-oA", "nmap-udp-comprehensive",
                    "-p", open_udp_ports, target
                ]
            state.phase_completed = "comprehensive_scan_udp"
            udp_success, output = run_nmap_command(udp_command, state)
            if not udp_success:
                print_warning(
                    "UDP comprehensive scan was not completed successfully")
            else:
                print_success(
                    "UDP comprehensive scan results saved in nmap-udp-comprehensive.* files")

        # Only mark as complete if all requested scans were successful
        if (not scan_tcp or tcp_success) and (not scan_udp or udp_success):
            state.phase_completed = "complete"
            save_state(state)
    else:
        print_warning("No open ports found to perform comprehensive scan")

    print_header("✨ SCAN COMPLETE")
    print_success("All scan phases completed successfully!")
    print_info("Results saved in the following files:")
    if scan_tcp and open_ports:
        print_info("- TCP comprehensive scan: nmap-tcp-comprehensive.*")
    if scan_udp and open_udp_ports:
        print_info("- UDP comprehensive scan: nmap-udp-comprehensive.*")
    clear_state()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nScript interrupted by user. Progress has been saved.")
        sys.exit(0)
