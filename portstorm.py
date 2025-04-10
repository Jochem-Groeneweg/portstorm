import subprocess
import re
import os
import sys
import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import html

"""
PortStorm - Advanced Network Scanning Tool
A powerful and aggressive network scanning utility built on Nmap
"""

# Global state variable for error logging
state = None

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
        # Changed from single target to list of targets
        self.targets: List[str] = []
        self.current_target: str = ""  # Track current target being scanned
        self.open_ports: Dict[str, List[str]] = {}  # IP -> list of open ports
        # IP -> list of open UDP ports
        self.open_udp_ports: Dict[str, List[str]] = {}
        # List of (start_port, end_port) tuples per IP
        self.scanned_ports: Dict[str, List[Tuple[int, int]]] = {}
        # List of (start_port, end_port) tuples per IP for UDP
        self.scanned_udp_ports: Dict[str, List[Tuple[int, int]]] = {}
        self.phase_completed: str = ""
        self.scan_type: str = ""
        self.scan_mode: str = "stealth"
        self.scan_udp: bool = False
        self.scan_timing: str = "normal"
        self.use_evasion: bool = False
        self.cloud_aware: bool = False
        self.timestamp: str = ""
        self.scan_command: List[str] = []
        self.scan_start_time: float = 0
        self.scan_end_time: float = 0
        self.error_count: int = 0
        self.last_error: str = ""
        self.progress: Dict[str, float] = {}  # Phase -> progress percentage
        self.network_folder: str = ""  # Added for network folder

    def to_dict(self) -> dict:
        return {
            "targets": self.targets,
            "current_target": self.current_target,
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
            "progress": self.progress,
            "network_folder": self.network_folder
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ScanState':
        state = cls()
        state.targets = data.get("targets", [])
        state.current_target = data.get("current_target", "")
        state.open_ports = data.get("open_ports", {})
        state.open_udp_ports = data.get("open_udp_ports", {})
        state.scanned_ports = data.get("scanned_ports", {})
        state.scanned_udp_ports = data.get("scanned_udp_ports", {})
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
        state.network_folder = data.get("network_folder", "")
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
    # Use global error log file if we don't have access to state
    error_log_path = ERROR_LOG_FILE
    # Try to get network folder from the main ScanState instance
    try:
        global state
        if state and hasattr(state, 'network_folder') and state.network_folder:
            error_log_path = os.path.join(
                state.network_folder, "nmap_scan_errors.log")
    except (NameError, AttributeError):
        pass
    with open(error_log_path, 'a') as f:
        f.write(f"[{timestamp}] {error_msg}\n")


def parse_xml_progress(xml_file: str) -> Tuple[Dict[str, List[str]], Dict[str, List[Tuple[int, int]]], int]:
    """Parse Nmap XML output to get open ports, scanned ranges per IP, and number of hosts up."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        open_ports = {}
        scanned_ranges = {}
        hosts_up = 0

        for host in root.findall('.//host'):
            ip = None
            for addr in host.findall('.//address'):
                if addr.get('addrtype') == 'ipv4':
                    ip = addr.get('addr')
                    break

            if not ip:
                continue

            # Check if host is up
            status = host.find('.//status')
            if status is not None and status.get('state') == 'up':
                hosts_up += 1

            open_ports[ip] = []
            scanned_ranges[ip] = []

            for port in host.findall('.//port'):
                if port.find('state').get('state') == 'open':
                    port_id = port.get('portid')
                    open_ports[ip].append(port_id)

            for port_range in host.findall('.//portused'):
                start = int(port_range.get('start'))
                end = int(port_range.get('end'))
                scanned_ranges[ip].append((start, end))

        return open_ports, scanned_ranges, hosts_up
    except ET.ParseError as e:
        log_error(f"Error parsing XML file: {str(e)}")
        return {}, {}, 0


def run_nmap_command(command: List[str], state: ScanState, resume_file: str = None, is_comprehensive: bool = False):
    """Run Nmap command and capture output with real-time progress tracking."""
    try:
        # Only show the starting message for non-comprehensive scans
        if not is_comprehensive:
            print_info(
                f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Run the command and capture output in real-time
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Initialize variables
        output = []
        last_progress = 0
        current_task = "Initializing scan..."
        hosts_completed = 0
        hosts_up = 0
        total_hosts = 0
        arp_scan_completed = False
        discovered_hosts = []  # Track discovered hosts

        # Clear the current line
        print("\033[K", end="\r")

        while True:
            line = process.stdout.readline()
            if not line:
                if process.poll() is not None:
                    break
                continue

            output.append(line)

            # Extract total hosts from ARP Ping Scan line
            if "Completed ARP Ping Scan" in line:
                total_hosts_match = re.search(
                    r'Completed ARP Ping Scan at .* \((\d+) total hosts\)', line)
                if total_hosts_match:
                    total_hosts = int(total_hosts_match.group(1))
                    arp_scan_completed = True

            # Extract hosts up from DNS resolution line
            if "Initiating Parallel DNS resolution" in line:
                hosts_up_match = re.search(
                    r'Initiating Parallel DNS resolution of (\d+) hosts', line)
                if hosts_up_match:
                    hosts_up = int(hosts_up_match.group(1))
                    hosts_completed = 0  # Reset completed count when starting new scan
                    # Clear the progress line and print ARP scan completion
                    print("\033[K", end="\r")  # Clear current line
                    print("\033[F", end="")    # Move up one line
                    print("\033[K", end="\r")  # Clear that line too
                    print("\n" + "=" * 80)
                    print(
                        f"{COLORS['GREEN']}✅ ARP Scan Complete{COLORS['END']}")
                    print(f"Found {hosts_up} hosts up in the network")
                    print("=" * 80)
                    if discovered_hosts and not is_comprehensive:
                        print(
                            f"{COLORS['GREEN']}Discovered Hosts:{COLORS['END']}")
                        print("-" * 80)
                        sorted_hosts = sorted(discovered_hosts, key=lambda x: [int(
                            ip) for ip in x.split("IP: ")[1].split()[0].split('.')])
                        for host in sorted_hosts:
                            print(host)
                        print("=" * 80)
                    print()  # Add a single newline after the section

            # Detect hosts that are up
            if "Host is up" in line or "arp-response" in line:
                if hosts_up == 0:  # Only increment if we haven't set hosts_up yet
                    hosts_up += 1
                    print("\033[K", end="\r")
                    print(
                        f"{COLORS['CYAN']}Progress: {last_progress:.1f}% | Task: {current_task}{COLORS['END']}", end="\r")
                    sys.stdout.flush()  # Force flush the output

            # Track completed SYN scans
            if "Completed SYN Stealth Scan against" in line:
                hosts_completed += 1
                if hosts_completed > hosts_up:  # Prevent overcounting
                    hosts_completed = hosts_up
                print("\033[K", end="\r")
                print(
                    f"{COLORS['CYAN']}Progress: {last_progress:.1f}% | Task: {current_task}{COLORS['END']}", end="\r")
                sys.stdout.flush()  # Force flush the output

            # Update progress based on current task
            if "SYN Stealth Scan" in current_task:
                # Calculate progress based on hosts completed
                if hosts_up > 0:
                    progress = (hosts_completed / hosts_up) * 100
                    if progress != last_progress:
                        last_progress = progress
                        print("\033[K", end="\r")
                        print(
                            f"{COLORS['CYAN']}Progress: {progress:.1f}% | Task: {current_task}{COLORS['END']}", end="\r")
                        sys.stdout.flush()  # Force flush the output

            # Extract progress and task information
            progress_match = re.search(r'About (\d+\.\d+)% done', line)
            task_match = re.search(r'undergoing (.*?) Scan', line)

            # Update hosts completed
            if "Nmap scan report for" in line:
                hosts_completed += 1
                print("\033[K", end="\r")
                print(
                    f"{COLORS['CYAN']}Progress: {last_progress:.1f}% | Task: {current_task}{COLORS['END']}", end="\r")
                sys.stdout.flush()  # Force flush the output

            if not re.search(r'undergoing (.*?) Scan', line):
                current_task = line.strip().split(':')[
                    0] if "NSE" in line or "SYN Stealth Scan" in line or "Service scan" in line or "OS detection" in line else "Scanning..."
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

            # Show initial progress if no progress yet
            if last_progress == 0 and not progress_match and not task_match:
                print("\033[K", end="\r")
                print(
                    f"{COLORS['CYAN']}Progress: 0.0% | Task: {current_task}{COLORS['END']}", end="\r")
                sys.stdout.flush()  # Force flush the output

        # Wait for the process to complete and get the return code
        return_code = process.wait()

        # Clear the final progress line
        print("\033[K", end="\r")

        # Check if the process completed successfully
        if return_code == 0:
            if not resume_file:  # Only show this message for non-comprehensive scans
                print_success(
                    f"Scan completed successfully! Found {hosts_up} hosts up.")
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


def scan_tcp_ports(target: str, state: ScanState, current_host: int, total_hosts: int) -> Optional[Dict[str, List[str]]]:
    """Scan TCP ports and return the open ports per IP."""
    print_header(f"🔍 TCP PORT SCAN - {target}")
    print_info(f"Scanning TCP ports for {target}")

    # Create host-specific folder
    host_folder = os.path.join(state.network_folder, target.replace('/', '_'))
    resume_file = os.path.join(
        host_folder, f"nmap-tcp-ports-{target.replace('/', '_')}")

    # Check if we can resume from previous scan
    if os.path.exists(f"{resume_file}.gnmap") and state.scanned_ports.get(target):
        print_info("Resuming previous TCP port scan...")
        command = ["nmap", "-v", "--resume", f"{resume_file}.gnmap", target]
    else:
        command = ["nmap", "-v", "-p-", "--open", "-T4", "-Pn",
                   "--stats-every", "5s", "-oA", resume_file, target]

    state.phase_completed = "tcp_port_scan"
    state.current_target = target
    success, output = run_nmap_command(command, state, resume_file)

    if not success:
        if output == "Interrupted by user":
            save_state(state)
        return None

    # Wait a moment to ensure the file is written
    time.sleep(1)

    # Parse results from XML
    if os.path.exists(f"{resume_file}.xml"):
        open_ports, scanned_ranges, hosts_up = parse_xml_progress(
            f"{resume_file}.xml")
        state.open_ports.update(open_ports)
        state.scanned_ports.update(scanned_ranges)

        if open_ports:
            # Sort IP addresses numerically
            sorted_ips = sorted(open_ports.keys(), key=lambda x: [
                                int(ip) for ip in x.split('.')])
            for ip in sorted_ips:
                ports = open_ports[ip]
                print_success(
                    f"Open TCP ports found for {ip}: {', '.join(ports)}")
            save_state(state)
            return open_ports
        else:
            print_warning(f"No open TCP ports found for {target}.")
            return None
    else:
        print_error(
            f"Failed to create scan results file. Command output: {output}")
        return None


def scan_udp_ports(target: str, state: ScanState, current_host: int, total_hosts: int) -> Optional[Dict[str, List[str]]]:
    """Scan UDP ports and return the open ports per IP."""
    print_header(f"🔍 UDP PORT SCAN PHASE (Host {current_host}/{total_hosts})")
    print_info(f"Scanning UDP ports for {target}")

    # Create host-specific folder
    host_folder = os.path.join(state.network_folder, target.replace('/', '_'))
    resume_file = os.path.join(
        host_folder, f"nmap-udp-ports-{target.replace('/', '_')}")

    if os.path.exists(f"{resume_file}.gnmap") and state.scanned_udp_ports.get(target):
        print_info("Resuming previous UDP port scan...")
        command = ["nmap", "-v", "--resume", f"{resume_file}.gnmap", target]
    else:
        command = ["nmap", "-v", "-sU", "--top-ports", "1000", "--open", "-Pn", "-T4",
                   "--stats-every", "5s", "-oA", resume_file, target]

    state.phase_completed = "udp_port_scan"
    state.current_target = target
    success, output = run_nmap_command(command, state, resume_file)

    if not success:
        if output == "Interrupted by user":
            save_state(state)
        return None

    # Wait a moment to ensure the file is written
    time.sleep(1)

    # Parse results from XML
    if os.path.exists(f"{resume_file}.xml"):
        open_ports, scanned_ranges, hosts_up = parse_xml_progress(
            f"{resume_file}.xml")
        state.open_udp_ports.update(open_ports)
        state.scanned_udp_ports.update(scanned_ranges)

        if open_ports:
            for ip, ports in open_ports.items():
                print_success(
                    f"Open UDP ports found for {ip}: {', '.join(ports)}")
            save_state(state)
            return open_ports
        else:
            print_warning(f"No open UDP ports found for {target}.")
            return None
    else:
        print_error(
            f"Failed to create scan results file. Command output: {output}")
        return None


def is_resumable_state(state: ScanState):
    """Check if the state is in a resumable condition."""
    if not state or not state.targets:
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


def parse_comprehensive_scan(xml_file: str) -> Dict:
    """Parse comprehensive Nmap scan results and return structured data."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        results = {
            'host': {},
            'ports': [],
            'os': {},
            'scripts': [],
            'vulnerabilities': []
        }

        # Get host information
        for host in root.findall('.//host'):
            # Host status
            status = host.find('.//status')
            if status is not None:
                results['host']['status'] = status.get('state', 'unknown')

            # Host addresses
            for addr in host.findall('.//address'):
                addr_type = addr.get('addrtype', 'unknown')
                results['host'][addr_type] = addr.get('addr', 'unknown')

            # OS information
            os_match = host.find('.//osmatch')
            if os_match is not None:
                results['os'] = {
                    'name': os_match.get('name', 'unknown'),
                    'accuracy': os_match.get('accuracy', 'unknown'),
                    'line': os_match.get('line', 'unknown')
                }

            # Port information
            for port in host.findall('.//port'):
                port_info = {
                    'port': port.get('portid', 'unknown'),
                    'protocol': port.get('protocol', 'unknown'),
                    'state': port.find('state').get('state', 'unknown') if port.find('state') is not None else 'unknown',
                    'service': {
                        'name': port.find('service').get('name', 'unknown') if port.find('service') is not None else 'unknown',
                        'product': port.find('service').get('product', '') if port.find('service') is not None else '',
                        'version': port.find('service').get('version', '') if port.find('service') is not None else '',
                        'extrainfo': port.find('service').get('extrainfo', '') if port.find('service') is not None else ''
                    }
                }

                # Script output
                for script in port.findall('.//script'):
                    script_info = {
                        'id': script.get('id', 'unknown'),
                        'output': script.get('output', '')
                    }
                    port_info['scripts'] = port_info.get(
                        'scripts', []) + [script_info]

                    # Check for vulnerabilities
                    if 'vulners' in script.get('id', '').lower():
                        current_vuln = None
                        for table in script.findall('.//table'):
                            # Start a new vulnerability if we find a CVE
                            if table.get('key', '').startswith('cve:'):
                                if current_vuln:
                                    results['vulnerabilities'].append(
                                        current_vuln)
                                current_vuln = {
                                    'cve': table.get('key', 'unknown'),
                                    'score': 'unknown',
                                    'summary': 'unknown'
                                }
                                # Get CVSS score
                                cvss_elem = table.find('.//elem[@key="cvss"]')
                                if cvss_elem is not None:
                                    current_vuln['score'] = cvss_elem.text
                                # Get summary
                                summary_elem = table.find(
                                    './/elem[@key="summary"]')
                                if summary_elem is not None:
                                    current_vuln['summary'] = summary_elem.text
                            # Add additional information to current vulnerability
                            elif current_vuln:
                                if table.get('key', '') == 'cvss':
                                    current_vuln['score'] = table.find(
                                        './/elem').text if table.find('.//elem') is not None else 'unknown'
                                elif table.get('key', '') == 'summary':
                                    current_vuln['summary'] = table.find(
                                        './/elem').text if table.find('.//elem') is not None else 'unknown'

                        # Add the last vulnerability if exists
                        if current_vuln:
                            results['vulnerabilities'].append(current_vuln)

                results['ports'].append(port_info)

        return results
    except ET.ParseError as e:
        log_error(f"Error parsing comprehensive scan XML: {str(e)}")
        return {}


def display_scan_results(results: Dict):
    """Display scan results in a neat, formatted way."""
    if not results:
        print_warning("No scan results to display")
        return

    # Display host information
    print_header("📡 HOST INFORMATION")
    if results['host']:
        print_info(f"Status: {results['host'].get('status', 'unknown')}")
        for addr_type, addr in results['host'].items():
            if addr_type != 'status':
                print_info(f"{addr_type.upper()}: {addr}")

    # Display OS information
    if results['os']:
        print_header("💻 OPERATING SYSTEM")
        print_info(f"OS: {results['os'].get('name', 'unknown')}")
        print_info(f"Accuracy: {results['os'].get('accuracy', 'unknown')}%")
        print_info(f"OS Details: {results['os'].get('line', 'unknown')}")

    # Display open ports and services
    if results['ports']:
        print_header("🔍 OPEN PORTS & SERVICES")
        for port in results['ports']:
            if port['state'] == 'open':
                service = port['service']
                print_info(f"Port {port['port']}/{port['protocol']}:")
                print_info(f"  Service: {service['name']}")
                if service['product']:
                    print_info(f"  Product: {service['product']}")
                if service['version']:
                    print_info(f"  Version: {service['version']}")
                if service['extrainfo']:
                    print_info(f"  Extra Info: {service['extrainfo']}")

                # Display script results
                if port.get('scripts'):
                    print_info("  Script Results:")
                    for script in port['scripts']:
                        print_info(f"    {script['id']}:")
                        for line in script['output'].split('\n'):
                            if line.strip():
                                print_info(f"      {line.strip()}")

    # Display vulnerabilities with improved filtering
    if results['vulnerabilities']:
        print_header("⚠️ VULNERABILITIES")
        # Group vulnerabilities by severity
        vulnerabilities_by_severity = {}
        for vuln in results['vulnerabilities']:
            try:
                severity = float(
                    vuln['score']) if vuln['score'] != 'unknown' else 0.0
                if severity >= 7.0:  # Only show high and critical vulnerabilities
                    if severity not in vulnerabilities_by_severity:
                        vulnerabilities_by_severity[severity] = []
                    vulnerabilities_by_severity[severity].append(vuln)
            except (ValueError, TypeError):
                continue  # Skip invalid scores

        # Sort by severity (descending) and display
        for severity in sorted(vulnerabilities_by_severity.keys(), reverse=True):
            print_warning(f"\nSeverity: {severity:.1f}")
            for vuln in vulnerabilities_by_severity[severity]:
                print_warning(f"Score: {vuln['score']}")
                if vuln['cve'] != 'unknown':
                    print_warning(f"CVE: {vuln['cve']}")
                if vuln['summary'] != 'unknown':
                    print_warning(f"Summary: {vuln['summary']}")
            print()  # Empty line for readability

        # Show vulnerability statistics
        total_vulns = len(results['vulnerabilities'])
        high_vulns = sum(1 for v in results['vulnerabilities']
                         if v['score'] != 'unknown' and float(v['score']) >= 7.0)
        print_info(f"\nVulnerability Statistics:")
        print_info(f"Total vulnerabilities found: {total_vulns}")
        print_info(f"High/Critical vulnerabilities: {high_vulns}")
        if total_vulns > 0:
            print_info(
                f"Percentage of high/critical vulnerabilities: {(high_vulns/total_vulns)*100:.1f}%")


def generate_pdf_report(results: Dict, filename: str = "portstorm_report.pdf"):
    """Generate a professional PDF report from scan results."""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center alignment
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#2C3E50')
    )

    # Add custom style for table cells with text wrapping
    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=10,
        leading=12,
        spaceBefore=6,
        spaceAfter=6,
        wordWrap='CJK'  # Enable text wrapping
    )

    # Title
    story.append(Paragraph("Nmap Scan Report", title_style))
    story.append(Paragraph(
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))

    # Host Information
    story.append(Paragraph("Host Information", heading_style))
    host_data = [
        [Paragraph("Status", cell_style), Paragraph(
            results['host'].get('status', 'unknown'), cell_style)],
        [Paragraph("IP Address", cell_style), Paragraph(
            results['host'].get('ipv4', 'unknown'), cell_style)],
        [Paragraph("MAC Address", cell_style), Paragraph(
            results['host'].get('mac', 'unknown'), cell_style)]
    ]
    host_table = Table(host_data, colWidths=[2*inch, 4*inch])
    host_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498DB')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP')  # Align content to top
    ]))
    story.append(host_table)
    story.append(Spacer(1, 20))

    # Operating System
    if results['os']:
        story.append(Paragraph("Operating System", heading_style))
        os_data = [
            [Paragraph("OS Name", cell_style), Paragraph(
                results['os'].get('name', 'unknown'), cell_style)],
            [Paragraph("Accuracy", cell_style), Paragraph(
                f"{results['os'].get('accuracy', 'unknown')}%", cell_style)],
            [Paragraph("Details", cell_style), Paragraph(
                results['os'].get('line', 'unknown'), cell_style)]
        ]
        os_table = Table(os_data, colWidths=[2*inch, 4*inch])
        os_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ECC71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')  # Align content to top
        ]))
        story.append(os_table)
        story.append(Spacer(1, 20))

    # Open Ports and Services
    if results['ports']:
        story.append(Paragraph("Open Ports and Services", heading_style))
        ports_data = [[
            Paragraph("Port", cell_style),
            Paragraph("Protocol", cell_style),
            Paragraph("Service", cell_style),
            Paragraph("Version", cell_style),
            Paragraph("Extra Info", cell_style)
        ]]
        for port in results['ports']:
            if port['state'] == 'open':
                service = port['service']
                ports_data.append([
                    Paragraph(port['port'], cell_style),
                    Paragraph(port['protocol'], cell_style),
                    Paragraph(service['name'], cell_style),
                    Paragraph(service['version'], cell_style),
                    Paragraph(service['extrainfo'], cell_style)
                ])

        ports_table = Table(ports_data, colWidths=[
            0.8*inch, 0.8*inch, 1.2*inch, 1.2*inch, 2*inch])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E74C3C')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')  # Align content to top
        ]))
        story.append(ports_table)
        story.append(Spacer(1, 20))

        # Script Results (only if there are any)
        has_script_results = any(port.get('scripts')
                                 for port in results['ports'] if port['state'] == 'open')
        if has_script_results:
            story.append(Paragraph("Script Results", heading_style))
            for port in results['ports']:
                if port['state'] == 'open' and port.get('scripts'):
                    story.append(
                        Paragraph(f"Port {port['port']}/{port['protocol']}", styles['Heading3']))
                    for script in port['scripts']:
                        story.append(
                            Paragraph(f"Script: {script['id']}", styles['Heading4']))
                        # Escape HTML-like tags in script output
                        escaped_output = html.escape(script['output'])
                        story.append(
                            Paragraph(escaped_output, styles['Normal']))
                        story.append(Spacer(1, 10))

    # Vulnerabilities
    if results['vulnerabilities']:
        story.append(Paragraph("Vulnerabilities", heading_style))
        # Group vulnerabilities by severity
        vulnerabilities_by_severity = {}
        for vuln in results['vulnerabilities']:
            try:
                severity = float(
                    vuln['score']) if vuln['score'] != 'unknown' else 0.0
                if severity >= 7.0:  # Only show high and critical vulnerabilities
                    if severity not in vulnerabilities_by_severity:
                        vulnerabilities_by_severity[severity] = []
                    vulnerabilities_by_severity[severity].append(vuln)
            except (ValueError, TypeError):
                continue

        # Sort by severity (descending) and display
        for severity in sorted(vulnerabilities_by_severity.keys(), reverse=True):
            story.append(
                Paragraph(f"Severity: {severity:.1f}", styles['Heading3']))
            for vuln in vulnerabilities_by_severity[severity]:
                vuln_data = []
                if vuln['cve'] != 'unknown':
                    vuln_data.append(
                        [Paragraph("CVE", cell_style), Paragraph(vuln['cve'], cell_style)])
                vuln_data.append(
                    [Paragraph("Score", cell_style), Paragraph(vuln['score'], cell_style)])
                if vuln['summary'] != 'unknown':
                    vuln_data.append(
                        [Paragraph("Summary", cell_style), Paragraph(vuln['summary'], cell_style)])

                vuln_table = Table(vuln_data, colWidths=[2*inch, 4*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F39C12')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(vuln_table)
                story.append(Spacer(1, 10))

    # Build the PDF
    doc.build(story)
    return filename


def generate_network_summary_pdf(all_results: Dict, filename: str = "portstorm_network_summary.pdf"):
    """Generate a comprehensive network summary PDF report."""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center alignment
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        textColor=colors.HexColor('#2C3E50')
    )

    # Add custom style for table cells with text wrapping
    cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontSize=10,
        leading=12,
        spaceBefore=6,
        spaceAfter=6,
        wordWrap='CJK'  # Enable text wrapping
    )

    # Title
    story.append(Paragraph("Network Scan Summary Report", title_style))
    story.append(Paragraph(
        f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))

    # Network Statistics
    story.append(Paragraph("Network Statistics", heading_style))

    # Calculate statistics
    total_hosts = len(all_results)
    service_stats = {}
    os_stats = {}
    open_ports_total = 0
    port_stats = {}  # Track ports by number
    protocol_stats = {}  # Track protocols (TCP/UDP)
    vulnerability_stats = {}  # Track vulnerabilities by severity
    common_services = {}  # Track common services and their versions

    for host, results in all_results.items():
        # Count services and ports
        for port in results.get('ports', []):
            if port['state'] == 'open':
                open_ports_total += 1
                port_num = port['port']
                protocol = port['protocol']
                service = port['service']['name']
                version = port['service'].get('version', 'unknown')

                # Update port statistics
                port_stats[port_num] = port_stats.get(port_num, 0) + 1

                # Update protocol statistics
                protocol_stats[protocol] = protocol_stats.get(protocol, 0) + 1

                # Update service statistics
                service_key = f"{service} ({version})" if version != 'unknown' else service
                service_stats[service_key] = service_stats.get(
                    service_key, 0) + 1

                # Track common services with host:port combinations
                if service not in common_services:
                    common_services[service] = {
                        'count': 0,
                        'hosts': {}  # host -> (port, version)
                    }
                common_services[service]['count'] += 1
                if host not in common_services[service]['hosts']:
                    common_services[service]['hosts'][host] = []
                common_services[service]['hosts'][host].append(
                    (port_num, version))

        # Count OS types
        if results.get('os'):
            os_name = results['os'].get('name', 'Unknown')
            os_stats[os_name] = os_stats.get(os_name, 0) + 1

        # Count vulnerabilities
        for vuln in results.get('vulnerabilities', []):
            severity = vuln.get('score', 'unknown')
            vulnerability_stats[severity] = vulnerability_stats.get(
                severity, 0) + 1

    # Create detailed statistics tables
    # Basic Statistics
    stats_data = [
        [Paragraph("Total Hosts Scanned", cell_style),
         Paragraph(str(total_hosts), cell_style)],
        [Paragraph("Total Open Ports", cell_style),
         Paragraph(str(open_ports_total), cell_style)],
        [Paragraph("Average Ports per Host", cell_style),
         Paragraph(f"{open_ports_total/total_hosts:.1f}" if total_hosts > 0 else "0", cell_style)]
    ]

    stats_table = Table(stats_data, colWidths=[3*inch, 1*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498DB')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 20))

    # Common Services with host:port combinations
    story.append(Paragraph("Common Services", heading_style))
    # Top 10 services
    for service, info in sorted(common_services.items(), key=lambda x: x[1]['count'], reverse=True)[:10]:
        story.append(
            Paragraph(f"{service} (Found on {info['count']} hosts)", styles['Heading3']))
        service_data = [[
            Paragraph("Host", cell_style),
            Paragraph("Port", cell_style),
            Paragraph("Version", cell_style)
        ]]
        for host, ports in info['hosts'].items():
            for port, version in ports:
                service_data.append([
                    Paragraph(host, cell_style),
                    Paragraph(str(port), cell_style),
                    Paragraph(version, cell_style)
                ])
        service_table = Table(service_data, colWidths=[2*inch, 1*inch, 3*inch])
        service_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2ECC71')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(service_table)
        story.append(Spacer(1, 10))

    # Most Common Open Ports
    story.append(Paragraph("Most Common Open Ports", heading_style))
    ports_data = [[Paragraph("Port", cell_style), Paragraph(
        "Count", cell_style), Paragraph("Percentage", cell_style)]]
    # Top 20 ports
    for port, count in sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:20]:
        percentage = (count / open_ports_total) * \
            100 if open_ports_total > 0 else 0
        ports_data.append([
            Paragraph(str(port), cell_style),
            Paragraph(str(count), cell_style),
            Paragraph(f"{percentage:.1f}%", cell_style)
        ])
    ports_table = Table(ports_data, colWidths=[1*inch, 1*inch, 1*inch])
    ports_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#9B59B6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(ports_table)
    story.append(Spacer(1, 20))

    # Vulnerabilities by Severity
    if vulnerability_stats:
        story.append(Paragraph("Vulnerabilities by Severity", heading_style))
        vuln_data = [[Paragraph("Severity", cell_style),
                      Paragraph("Count", cell_style)]]
        for severity, count in sorted(vulnerability_stats.items(), key=lambda x: float(x[0]) if x[0] != 'unknown' else 0, reverse=True):
            vuln_data.append([
                Paragraph(severity, cell_style),
                Paragraph(str(count), cell_style)
            ])
        vuln_table = Table(vuln_data, colWidths=[3*inch, 2*inch])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F39C12')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ECF0F1')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(vuln_table)

    # Build the PDF
    doc.build(story)
    return filename


def main():
    """Main function to orchestrate the scan process."""
    global state

    # Check if nmap is installed
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_error(
            "Nmap is not installed or not in PATH. Please install nmap first.")
        return

    # Initialize or load state
    state = load_state() or ScanState()

    print_header("⚙️  SCAN CONFIGURATION")
    print_info("Network Name:")
    # Get network alias
    network_alias = input(
        f"{COLORS['CYAN']}Enter a name for this network scan: {COLORS['END']}").strip()
    if not network_alias:
        network_alias = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # Create network folder
    network_folder = os.path.join(os.getcwd(), network_alias)
    os.makedirs(network_folder, exist_ok=True)
    state.network_folder = network_folder  # Store network folder in state

    print()  # Add spacing
    print_info("Target IP/Range:")
    if state.targets:
        print_header("📊 PREVIOUS SCAN STATE")
        print_info("Targets: " + ", ".join(state.targets))
        print_info(f"Last phase: {state.phase_completed}")
        for target in state.targets:
            if state.open_ports.get(target):
                print_info(
                    f"Open TCP ports found for {target}: {', '.join(state.open_ports[target])}")
            if state.open_udp_ports.get(target):
                print_info(
                    f"Open UDP ports found for {target}: {', '.join(state.open_udp_ports[target])}")
        print_info(f"Timestamp: {state.timestamp}")

        if is_resumable_state(state):
            resume = input(
                f"{COLORS['CYAN']}Do you want to resume the previous scan? (y/n): {COLORS['END']}").strip().lower()
            if resume == 'y':
                targets = state.targets
            else:
                clear_state()
                targets = input(
                    f"{COLORS['CYAN']}Enter target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24): {COLORS['END']}").strip().split(',')
        else:
            print_warning(
                "Previous scan was not in a resumable state. Starting new scan.")
            clear_state()
            targets = input(
                f"{COLORS['CYAN']}Enter target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24): {COLORS['END']}").strip().split(',')
    else:
        targets = input(
            f"{COLORS['CYAN']}Enter target IP address or range (e.g., 192.168.1.1 or 192.168.1.0/24): {COLORS['END']}").strip().split(',')

    if not targets or not all(targets):
        print_error("Invalid target(s). Exiting.")
        return

    print_header("🔍 SCAN TYPE SELECTION")
    print_info("1. TCP scan only")
    print_info("2. UDP scan only")
    print_info("3. Both TCP and UDP scans")

    while True:
        try:
            scan_choice = int(
                input(f"{COLORS['CYAN']}Enter your choice (1-3): {COLORS['END']}"))
            if scan_choice in [1, 2, 3]:
                break
            print_error("Please enter a valid choice (1-3)")
        except ValueError:
            print_error("Please enter a number between 1 and 3")

    # Set scan type flags based on user choice
    scan_tcp = scan_choice in [1, 3]  # True for choices 1 and 3
    scan_udp = scan_choice in [2, 3]  # True for choices 2 and 3

    # If targets changed, clear the state
    if state.targets and set(state.targets) != set(targets):
        print_warning("Targets changed. Starting new scan.")
        clear_state()
        state = ScanState()
        state.network_folder = network_folder

    # Create host folders
    for target in targets:
        host_folder = os.path.join(network_folder, target.replace('/', '_'))
        os.makedirs(host_folder, exist_ok=True)

    state.targets = targets
    save_state(state)

    all_open_ports = {}
    all_open_udp_ports = {}
    total_hosts = len(targets)

    # Step 1: Full TCP port scan
    if scan_tcp and (not state.phase_completed or state.phase_completed == "tcp_port_scan"):
        for i, target in enumerate(targets, 1):
            open_ports = scan_tcp_ports(target, state, i, total_hosts)
            if open_ports:
                all_open_ports.update(open_ports)
            else:
                print_warning(f"No open TCP ports found for {target}.")
    else:
        all_open_ports = {ip: ",".join(ports)
                          for ip, ports in state.open_ports.items()}

    # Step 2: Full UDP port scan
    if scan_udp and (not state.phase_completed or state.phase_completed in ["tcp_port_scan", "udp_port_scan"]):
        print_header("🔍 FULL UDP PORT SCAN")
        for i, target in enumerate(targets, 1):
            print_info(f"Scanning all 65535 UDP ports for {target}")
            open_udp_ports = scan_udp_ports(target, state, i, total_hosts)
            if open_udp_ports:
                all_open_udp_ports.update(open_udp_ports)
            else:
                print_warning(f"No open UDP ports found for {target}.")
    else:
        all_open_udp_ports = {ip: ",".join(
            ports) for ip, ports in state.open_udp_ports.items()}

    # Step 3: Comprehensive scan on all open ports
    if (scan_tcp and all_open_ports) or (scan_udp and all_open_udp_ports):
        print_header("🔬 COMPREHENSIVE SCAN")
        print_info(
            "Performing detailed service and vulnerability scan on open ports...")

        tcp_success = False
        udp_success = False

        # Run comprehensive scan for TCP ports
        if scan_tcp and all_open_ports and (not state.phase_completed or
                                            state.phase_completed in ["tcp_port_scan", "udp_port_scan", "comprehensive_scan_tcp"]):
            print_info("Scanning TCP ports...")
            # Sort IP addresses numerically before scanning
            sorted_ips = sorted(all_open_ports.keys(), key=lambda x: [
                                int(ip) for ip in x.split('.')])
            for target in sorted_ips:
                ports = all_open_ports[target]
                # Format ports as comma-separated string
                ports_str = ','.join(ports) if isinstance(
                    ports, list) else str(ports)

                # Create folder for this specific IP
                ip_folder = os.path.join(
                    state.network_folder, target.replace('/', '_'))
                os.makedirs(ip_folder, exist_ok=True)
                output_prefix = os.path.join(ip_folder, f"tcp-comprehensive")

                # Check if we're on Windows
                if os.name == 'nt':
                    tcp_command = [
                        "nmap", "-v", "-sV", "-O", "-sC", "-T4", "-Pn",
                        "--script=vulners,http-enum,ftp-anon,smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010",
                        "--version-all", "--traceroute",
                        "--stats-every", "5s",
                        "-oA", output_prefix,
                        "-p", ports_str, target
                    ]
                else:
                    tcp_command = [
                        "sudo", "nmap", "-v", "-sV", "-O", "-sC", "-T4", "-Pn",
                        "--script=vulners,http-enum,ftp-anon,smb-os-discovery,smb-enum-shares,smb-vuln-ms17-010",
                        "--version-all", "--traceroute",
                        "--stats-every", "5s",
                        "-oA", output_prefix,
                        "-p", ports_str, target
                    ]
                state.phase_completed = "comprehensive_scan_tcp"
                state.current_target = target
                print_info(
                    f"Starting comprehensive scan for {target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                tcp_success, output = run_nmap_command(
                    tcp_command, state, resume_file=output_prefix, is_comprehensive=True)
                if not tcp_success:
                    print_warning(
                        f"TCP comprehensive scan for {target} was not completed successfully")
                else:
                    print_success(
                        f"TCP comprehensive scan for {target} completed successfully")
                    # Parse and display TCP results
                    tcp_results = parse_comprehensive_scan(
                        f"{output_prefix}.xml")
                    display_scan_results(tcp_results)
                    # Generate PDF report
                    pdf_file = generate_pdf_report(
                        tcp_results, os.path.join(ip_folder, f"tcp-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"))
                    print_success(f"TCP scan report generated: {pdf_file}")

        # Run comprehensive scan for UDP ports
        if scan_udp and all_open_udp_ports and (not state.phase_completed or
                                                state.phase_completed in ["tcp_port_scan", "udp_port_scan", "comprehensive_scan_udp"]):
            print_info("Scanning UDP ports...")
            # Sort IP addresses numerically before scanning
            sorted_ips = sorted(all_open_udp_ports.keys(), key=lambda x: [
                                int(ip) for ip in x.split('.')])
            for target in sorted_ips:
                ports = all_open_udp_ports[target]
                # Create folder for this specific IP
                ip_folder = os.path.join(
                    state.network_folder, target.replace('/', '_'))
                os.makedirs(ip_folder, exist_ok=True)
                output_prefix = os.path.join(ip_folder, f"udp-comprehensive")

                # Check if we're on Windows
                if os.name == 'nt':
                    udp_command = [
                        "nmap", "-v", "-sU", "-sV", "-O", "-sC", "-T4", "-Pn",
                        "--script=dns-nsid,ntp-monlist,snmp-info,dhcp-discover,tftp-enum",
                        "--version-all",
                        "--stats-every", "5s",
                        "-oA", output_prefix,
                        "-p", ports, target
                    ]
                else:
                    udp_command = [
                        "sudo", "nmap", "-v", "-sU", "-sV", "-O", "-sC", "-T4", "-Pn",
                        "--script=dns-nsid,ntp-monlist,snmp-info,dhcp-discover,tftp-enum",
                        "--version-all",
                        "--stats-every", "5s",
                        "-oA", output_prefix,
                        "-p", ports, target
                    ]
                state.phase_completed = "comprehensive_scan_udp"
                state.current_target = target
                print_info(
                    f"Starting comprehensive scan for {target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                udp_success, output = run_nmap_command(
                    udp_command, state, resume_file=output_prefix, is_comprehensive=True)
                if not udp_success:
                    print_warning(
                        f"UDP comprehensive scan for {target} was not completed successfully")
                else:
                    print_success(
                        f"UDP comprehensive scan for {target} completed successfully")
                    # Parse and display UDP results
                    udp_results = parse_comprehensive_scan(
                        f"{output_prefix}.xml")
                    display_scan_results(udp_results)
                    # Generate PDF report
                    pdf_file = generate_pdf_report(
                        udp_results, os.path.join(ip_folder, f"udp-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"))
                    print_success(f"UDP scan report generated: {pdf_file}")

        # After all scans are complete, generate the network summary
        if (scan_tcp and all_open_ports) or (scan_udp and all_open_udp_ports):
            print_header("📊 GENERATING NETWORK SUMMARY")
            all_results = {}

            # Collect all scan results
            for target in all_open_ports.keys():
                ip_folder = os.path.join(
                    state.network_folder, target.replace('/', '_'))
                tcp_results = parse_comprehensive_scan(
                    os.path.join(ip_folder, "tcp-comprehensive.xml"))
                if tcp_results:
                    all_results[target] = tcp_results

            for target in all_open_udp_ports.keys():
                ip_folder = os.path.join(
                    state.network_folder, target.replace('/', '_'))
                udp_results = parse_comprehensive_scan(
                    os.path.join(ip_folder, "udp-comprehensive.xml"))
                if udp_results:
                    if target in all_results:
                        # Merge UDP results with existing TCP results
                        all_results[target]['ports'].extend(
                            udp_results.get('ports', []))
                    else:
                        all_results[target] = udp_results

            # Generate the summary PDF in the network folder
            summary_pdf = generate_network_summary_pdf(all_results, os.path.join(
                state.network_folder, "network_summary_report.pdf"))
            print_success(f"Network summary report generated: {summary_pdf}")
    else:
        print_warning("No open ports found to perform comprehensive scan")

    print_header("✨ SCAN COMPLETE")
    print_success("All scan phases completed successfully!")
    print_info("Results saved in the following files:")
    if scan_tcp and all_open_ports:
        for target in all_open_ports.keys():
            print_info(
                f"- TCP comprehensive scan for {target}: nmap-tcp-comprehensive-{target.replace('/', '_')}.xml")
            print_info(
                f"- TCP scan report for {target}: nmap-tcp-report-{target.replace('/', '_')}-*.pdf")
    if scan_udp and all_open_udp_ports:
        for target in all_open_udp_ports.keys():
            print_info(
                f"- UDP comprehensive scan for {target}: nmap-udp-comprehensive-{target.replace('/', '_')}.xml")
            print_info(
                f"- UDP scan report for {target}: nmap-udp-report-{target.replace('/', '_')}-*.pdf")
    clear_state()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nScript interrupted by user. Progress has been saved.")
        sys.exit(0)
