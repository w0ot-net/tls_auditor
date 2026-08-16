#!/usr/bin/env python3
"""
SSL/TLS Cipher Security Auditor
Wraps nmap ssl-enum-ciphers and sslv2 scripts to identify insecure TLS configurations.
Requires Python 3.8+
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# INSECURE CIPHER DEFINITIONS
# =============================================================================

# Deprecated protocols - report ALL ciphers as insecure
DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

# CBC ciphers vulnerable to GOLDENDOODLE/POODLE variants
CBC_CIPHERS = {
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
}

# Weak ciphers (RC4, DES, export, NULL, anonymous)
WEAK_CIPHERS = {
    # RC4 - broken
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    "TLS_DHE_RSA_WITH_RC4_128_SHA",
    # DES - weak
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    # 3DES - SWEET32
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    # NULL encryption
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_ECDHE_RSA_WITH_NULL_SHA",
    "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    # Anonymous key exchange
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_anon_WITH_RC4_128_MD5",
    "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDH_anon_WITH_RC4_128_SHA",
    "TLS_ECDH_anon_WITH_NULL_SHA",
}

# Grades considered weak (B through F)
WEAK_GRADES = {"B", "C", "D", "E", "F"}

# Canonical protocol list (single source of truth)
PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")


def normalize_cipher_value(value: str) -> str:
    """Normalize a CSV cipher cell while preserving sentinel values."""
    if not value:
        return "-"

    value = value.strip()
    if not value or value == "-":
        return "-"
    if value == "All":
        return "All"

    ciphers = {line.strip() for line in value.splitlines() if line.strip()}
    if not ciphers:
        return "-"
    return "\n".join(sorted(ciphers))


def format_host_port(host: str, port: str) -> str:
    """Format host:port, bracketing IPv6 literals."""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


# =============================================================================
# INPUT PARSING
# =============================================================================


def normalize_port(port: str) -> str:
    """Validate and normalize a numeric TCP port."""
    if not port.isdigit():
        raise ValueError(f"invalid port: {port or '<empty>'}")

    port_number = int(port)
    if not 0 <= port_number <= 65535:
        raise ValueError(f"port out of range: {port}")
    return str(port_number)


def split_explicit_host_port(value: str) -> Optional[Tuple[str, str]]:
    """Return an explicit host/port pair, or None for a bare host."""
    value = value.strip()
    if not value:
        raise ValueError("host is empty")

    if value.startswith("["):
        match = re.fullmatch(r"\[([^\[\]]+)\]:(\d+)", value)
        if match is None or ":" not in match.group(1):
            raise ValueError(f"invalid bracketed IPv6 endpoint: {value}")
        return match.group(1), normalize_port(match.group(2))

    if "[" in value or "]" in value:
        raise ValueError(f"invalid bracketed IPv6 endpoint: {value}")

    colon_count = value.count(":")
    if colon_count == 0:
        return None
    if colon_count > 1:
        # Unbracketed IPv6 is a bare host. Brackets are required to add a port.
        return None

    host, port = value.rsplit(":", 1)
    if not host or any(char.isspace() for char in host):
        raise ValueError(f"invalid host:port endpoint: {value}")
    return host, normalize_port(port)


def parse_host_port(
    value: str, default_port: Optional[str] = None
) -> Tuple[str, str]:
    """Parse an endpoint, applying default_port only when no port is present."""
    explicit = split_explicit_host_port(value)
    if explicit is not None:
        return explicit
    if default_port is None:
        raise ValueError(f"missing port: {value.strip()}")
    return value.strip(), normalize_port(default_port)


def parse_rich_input(input_file: str) -> List[Dict[str, str]]:
    """
    Parse rich input format with IP, hostname, and service columns.
    Format: IP<tab>hostname<tab>service (port/tcp)
    """
    targets = []

    with open(input_file, "r") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            # Split on tabs or multiple spaces
            parts = re.split(r"\t+|\s{2,}", line)

            if len(parts) >= 3:
                ip = parts[0].strip()
                hostname = parts[1].strip()
                service_info = parts[2].strip()

                # Extract the port from values such as "www (443/tcp)".
                port_match = re.search(r"\((\d+)/tcp\)", service_info)
                if port_match:
                    try:
                        port = normalize_port(port_match.group(1))
                    except ValueError as exc:
                        raise ValueError(
                            f"{input_file}:{line_number}: {exc}"
                        ) from exc
                    service = re.sub(r"\s*\(\d+/tcp\)", "", service_info).strip()

                    targets.append({
                        "ip": ip,
                        "hostname": hostname if hostname != "-" else "",
                        "port": port,
                        "service": service,
                    })

    return targets


def parse_simple_input(input_file: str) -> List[str]:
    """Parse simple input format with one IP/hostname per line."""
    hosts = []

    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line)

    return sorted(set(hosts))


def parse_hostport_input(input_file: str) -> List[Dict[str, str]]:
    """Parse host:port input, defaulting bare hosts to port 443."""
    targets = []
    seen: Set[Tuple[str, str]] = set()

    with open(input_file, "r") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                host, port = parse_host_port(line, default_port="443")
            except ValueError as exc:
                raise ValueError(f"{input_file}:{line_number}: {exc}") from exc

            key = (host, port)
            if key in seen:
                continue
            seen.add(key)

            targets.append({"ip": host, "hostname": "", "port": port, "service": ""})

    return targets


def detect_input_format(input_file: str) -> str:
    """Detect whether input file is 'rich', 'hostport', or 'simple' format."""
    has_hostport = False
    with open(input_file, "r") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if (
                ("\t" in line or re.search(r"\s{2,}", line))
                and re.search(r"\(\d+/tcp\)", line)
            ):
                return "rich"

            try:
                if split_explicit_host_port(line) is not None:
                    has_hostport = True
            except ValueError as exc:
                raise ValueError(f"{input_file}:{line_number}: {exc}") from exc

    return "hostport" if has_hostport else "simple"


def build_scan_jobs(targets: List[Dict[str, str]]) -> List[Tuple[str, List[str]]]:
    """Group rich targets by port without creating new host/port pairs."""
    hosts_by_port: Dict[str, Set[str]] = {}

    for t in targets:
        hosts_by_port.setdefault(t["port"], set()).add(t["ip"])

    return [
        (port, sorted(hosts_by_port[port]))
        for port in sorted(hosts_by_port, key=int)
    ]


def scan_xml_path(
    output_prefix: str,
    port: str,
    round_number: int,
    job_count: int,
    round_count: int,
) -> str:
    """Build a collision-free XML path while preserving legacy names."""
    if job_count == 1 and round_count == 1:
        return f"{output_prefix}.xml"

    suffixes = []
    if job_count > 1:
        suffixes.append(f"port{port}")
    if round_count > 1:
        suffixes.append(f"round{round_number}")
    return f"{output_prefix}_{'_'.join(suffixes)}.xml"


# =============================================================================
# NMAP EXECUTION
# =============================================================================

def run_nmap(
    input_file: str,
    ports: str,
    xml_output: str,
    timing: Optional[str] = None,
) -> bool:
    """Run nmap with ssl-enum-ciphers and sslv2 scripts."""
    cmd = [
        "nmap",
        "-Pn",
        "-p", ports,
        "-iL", input_file,
        "--script", "ssl-enum-ciphers,sslv2",
        "-oX", xml_output,
    ]

    # Only add timing flag if specified
    if timing is not None:
        cmd.insert(2, f"-T{timing}")

    print(f"[*] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[!] nmap stderr: {result.stderr}", file=sys.stderr)
        return result.returncode == 0
    except FileNotFoundError:
        print("[!] Error: nmap not found. Please install nmap.", file=sys.stderr)
        return False


# =============================================================================
# XML PARSING
# =============================================================================

def is_cipher_insecure(cipher_name: str, grade: str, protocol: str) -> bool:
    """Determine if a cipher should be reported as insecure."""
    # All ciphers in deprecated protocols are insecure
    if protocol in DEPRECATED_PROTOCOLS:
        return True

    # Weak grades (B-F)
    if grade in WEAK_GRADES:
        return True

    # CBC ciphers (GOLDENDOODLE/POODLE)
    if "CBC" in cipher_name or cipher_name in CBC_CIPHERS:
        return True

    # Known weak ciphers
    if cipher_name in WEAK_CIPHERS:
        return True

    return False


def parse_nmap_xml(
    xml_file: str,
    rich_targets: Optional[List[Dict[str, str]]] = None,
) -> List[Dict]:
    """Parse nmap XML output and extract SSL/TLS cipher info."""
    results = []

    # Build hostname lookup from rich targets if available
    hostname_lookup = {}
    service_lookup = {}
    if rich_targets:
        for t in rich_targets:
            key = f"{t['ip']}:{t['port']}"
            if t["hostname"]:
                hostname_lookup[key] = t["hostname"]
            if t.get("service"):
                service_lookup[key] = t["service"]

    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        # Get IP address
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        # Check host status
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Get hostname from nmap if available. Prefer the user-supplied name
        # (the one carried in from the input file, echoed by nmap as
        # type="user") over a reverse-DNS PTR, which is often an ephemeral
        # cloud rDNS entry that nmap may list first.
        nmap_hostname = ""
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            for hostname_elem in hostnames_elem.findall("hostname"):
                name = (hostname_elem.get("name") or "").strip()
                if not name:
                    continue
                if hostname_elem.get("type") == "user":
                    nmap_hostname = name
                    break
                if not nmap_hostname:
                    nmap_hostname = name

        # Process each port
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            port_id = port.get("portid")

            # Check if port is open
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            # Get service info
            service = port.find("service")
            service_name = ""
            if service is not None:
                service_name = service.get("name", "")

            # Look for ssl-enum-ciphers script output
            ssl_script = port.find("script[@id='ssl-enum-ciphers']")
            sslv2_script = port.find("script[@id='sslv2']")

            if ssl_script is None and sslv2_script is None:
                continue

            # Initialize cipher data for each protocol
            cipher_data = {p: [] for p in PROTOCOLS}
            protocols_present = set()  # Track protocols seen, even when empty

            # Parse ssl-enum-ciphers output
            if ssl_script is not None:
                for table in ssl_script.findall("table"):
                    protocol = table.get("key", "")
                    if protocol not in cipher_data:
                        continue

                    # Mark this protocol as present
                    protocols_present.add(protocol)

                    # Find ciphers table within this protocol
                    ciphers_table = table.find("table[@key='ciphers']")
                    if ciphers_table is None:
                        continue

                    for cipher_table in ciphers_table.findall("table"):
                        cipher_name = ""
                        grade = ""

                        for elem in cipher_table.findall("elem"):
                            key = elem.get("key", "")
                            if key == "name":
                                cipher_name = elem.text or ""
                            elif key == "strength":
                                grade = elem.text or ""

                        if cipher_name and is_cipher_insecure(
                            cipher_name, grade, protocol
                        ):
                            cipher_data[protocol].append(cipher_name)

            # Parse sslv2 script output
            if sslv2_script is not None:
                output = sslv2_script.get("output", "")
                if "SSLv2 supported" in output:
                    # Mark SSLv2 as present
                    protocols_present.add("SSLv2")

                    # Extract SSLv2 ciphers
                    cipher_tables = sslv2_script.findall(
                        ".//table[@key='ciphers']/table"
                    )
                    for cipher_table in cipher_tables:
                        for elem in cipher_table.findall("elem[@key='name']"):
                            if elem.text:
                                cipher_data["SSLv2"].append(elem.text)

                    # Fallback: parse from output text
                    if not cipher_data["SSLv2"]:
                        for match in re.findall(r"SSL2_\w+", output):
                            cipher_data["SSLv2"].append(match)

            # Determine hostname to display
            lookup_key = f"{ip}:{port_id}"
            hostname = hostname_lookup.get(lookup_key, nmap_hostname)
            host_display = hostname if hostname else ip

            # Determine service name for affected systems
            svc = service_lookup.get(lookup_key, service_name)
            if not svc:
                svc = "ssl"

            # Format cipher output
            def format_ciphers(
                ciphers: List[str], protocol: str, present: bool
            ) -> str:
                if protocol in DEPRECATED_PROTOCOLS:
                    # Report "All" even if Nmap omitted the cipher list.
                    if present or ciphers:
                        return "All"
                    return "-"
                if not ciphers:
                    return "-"
                return normalize_cipher_value("\n".join(ciphers))

            # Check if there are any issues
            has_issues = any(cipher_data[p] for p in PROTOCOLS) or any(
                p in protocols_present for p in DEPRECATED_PROTOCOLS
            )

            if has_issues:
                row = {
                    "Host:Port": format_host_port(host_display, port_id),
                    "ip": ip,
                    "hostname": hostname if hostname else "-",
                    "port": port_id,
                    "service": svc,
                }
                for protocol in PROTOCOLS:
                    row[protocol] = format_ciphers(
                        cipher_data[protocol],
                        protocol,
                        protocol in protocols_present,
                    )
                results.append(row)

    return results


def merge_result_row(existing: Dict, new: Dict) -> None:
    """Merge cipher findings from new into an existing Host:Port row."""
    for proto in PROTOCOLS:
        existing_value = existing.get(proto, "-")
        new_value = new.get(proto, "-")

        if existing_value == "-":
            existing[proto] = new_value
        elif new_value == "All":
            existing[proto] = "All"
        elif new_value != "-" and existing_value != "All":
            existing[proto] = normalize_cipher_value(
                f"{existing_value}\n{new_value}"
            )


def aggregate_results(
    xml_files: List[str], rich_targets: Optional[List[Dict[str, str]]] = None
) -> List[Dict]:
    """
    Aggregate cipher findings from multiple nmap XML files.
    Deduplicates findings across rounds - a cipher is reported if found in ANY round.
    """
    seen_host_ports = {}  # host:port -> merged result dict

    for xml_file in xml_files:
        results = parse_nmap_xml(xml_file, rich_targets)

        for row in results:
            host_port = row["Host:Port"]

            if host_port not in seen_host_ports:
                seen_host_ports[host_port] = row.copy()
            else:
                merge_result_row(seen_host_ports[host_port], row)

    return list(seen_host_ports.values())


def read_cipher_csv(csv_file: str) -> List[Dict]:
    """Read a cipher audit CSV and return result dicts compatible with merge."""
    results = []
    with open(csv_file, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            host_port = row.get("Host:Port", "")
            if not host_port:
                continue

            try:
                host, port = parse_host_port(host_port)
            except ValueError as exc:
                raise ValueError(
                    f"{csv_file}:{reader.line_num}: {exc}"
                ) from exc

            result = {
                "Host:Port": host_port,
                "ip": host,
                "hostname": "-",
                "port": port,
                "service": "ssl",
            }
            for proto in PROTOCOLS:
                result[proto] = normalize_cipher_value(row.get(proto, "-"))

            results.append(result)

    return results


def merge_cipher_csvs(csv_files: List[str]) -> List[Dict]:
    """Merge multiple cipher audit CSVs, deduplicating by Host:Port."""
    seen: Dict[str, Dict] = {}

    for csv_file in csv_files:
        for row in read_cipher_csv(csv_file):
            host_port = row["Host:Port"]

            if host_port not in seen:
                seen[host_port] = row.copy()
            else:
                merge_result_row(seen[host_port], row)

    return list(seen.values())


# =============================================================================
# OUTPUT GENERATION
# =============================================================================

def write_cipher_csv(results: List[Dict], output_file: str) -> None:
    """Write cipher table to CSV file."""
    protocols_with_findings = [
        proto for proto in PROTOCOLS
        if any(normalize_cipher_value(r.get(proto, "-")) != "-" for r in results)
    ]
    fieldnames = ["Host:Port"] + protocols_with_findings
    normalized_results = []
    for row in results:
        normalized_row = row.copy()
        for proto in PROTOCOLS:
            normalized_row[proto] = normalize_cipher_value(row.get(proto, "-"))
        normalized_results.append(normalized_row)

    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(normalized_results)

    print(f"[+] Cipher table written to: {output_file}")


def write_affected_csv(results: List[Dict], output_file: str) -> None:
    """Write affected systems CSV file."""
    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        for r in results:
            writer.writerow([
                r["ip"],
                r["hostname"],
                f"{r['service']} ({r['port']}/tcp)"
            ])

    print(f"[+] Affected systems written to: {output_file}")


def print_summary(results: List[Dict]) -> None:
    """Print summary of findings."""
    if not results:
        print("[*] No SSL/TLS services with issues found")
        return

    print(f"\n[+] Found {len(results)} host(s) with insecure ciphers:")

    # Count by protocol
    proto_counts = {p: 0 for p in PROTOCOLS}

    for r in results:
        for proto in PROTOCOLS:
            if r.get(proto, "-") != "-":
                proto_counts[proto] += 1

    for proto in PROTOCOLS:
        count = proto_counts[proto]
        if count > 0:
            print(f"    {proto}: {count} host(s)")


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit SSL/TLS servers for insecure ciphers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Input formats:
  Simple (requires -p):
    192.168.1.1
    192.168.1.2
    example.com

  Host:port (auto-detects ports):
    192.168.1.1:443
    192.168.1.2:8443
    example.com:636
    [2001:db8::10]:443

  Rich (auto-detects ports):
    172.16.1.10    AD02.example.com    ldaps (636/tcp)
    172.16.1.41    Web.example.com     www (443/tcp)
    172.16.1.42    -                   https (443/tcp)

Examples:
  %(prog)s -i hosts.txt -p 443
  %(prog)s -i hosts.txt -p 443,636,3389
  %(prog)s -i tls.txt
  %(prog)s -i rich_targets.txt
  %(prog)s --xml existing_scan.xml -o results.csv
  %(prog)s --merge scan1.csv scan2.csv -o combined
        """,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i", "--input",
        help="Input file (simple, host:port, or rich format)"
    )
    input_group.add_argument(
        "--xml",
        help="Parse existing nmap XML file instead of scanning"
    )
    input_group.add_argument(
        "--merge",
        nargs="+",
        metavar="CSV",
        help="Merge multiple cipher audit CSV files (not affected CSVs)"
    )

    parser.add_argument(
        "-p", "--ports",
        help="Comma-separated list of ports to scan (required for simple input format)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output CSV file prefix (default: ssl_audit_YYYYMMDD_HHMMSS)"
    )

    parser.add_argument(
        "--keep-xml",
        action="store_true",
        help="Keep intermediate nmap XML file(s)"
    )

    parser.add_argument(
        "-T", "--timing",
        type=str,
        default=None,
        metavar="0-5",
        help="nmap timing template (0-5). If not specified, nmap uses its default."
    )

    parser.add_argument(
        "--rounds",
        type=int,
        default=1,
        choices=range(1, 11),
        metavar="N",
        help=(
            "Number of times to run the scan (1-10). Results are aggregated. "
            "Default: 1"
        ),
    )

    args = parser.parse_args()

    # Handle --merge mode early; it does not create intermediate XML.
    if args.merge:
        for f in args.merge:
            if not Path(f).is_file():
                print(f"[!] Error: CSV file not found: {f}", file=sys.stderr)
                sys.exit(1)

        print(f"[*] Merging {len(args.merge)} CSV file(s)...")
        try:
            results = merge_cipher_csvs(args.merge)
        except (OSError, ValueError, csv.Error) as exc:
            print(f"[!] Error: {exc}", file=sys.stderr)
            sys.exit(1)

        if not results:
            print("[*] No results found in input files")
        else:
            output_prefix = args.output if args.output else "merged"
            if output_prefix.endswith(".csv"):
                output_prefix = output_prefix[:-4]

            print_summary(results)
            write_cipher_csv(results, f"{output_prefix}.csv")
            write_affected_csv(results, f"{output_prefix}_affected.csv")

        print("[+] Done")
        return

    # Validate timing template if specified.
    if args.timing is not None:
        valid_timing = ["0", "1", "2", "3", "4", "5"]
        if args.timing not in valid_timing:
            parser.error(f"Invalid timing template: {args.timing}. Must be 0-5.")

    # Generate output filename prefix
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = args.output if args.output else f"ssl_audit_{timestamp}"

    # Remove .csv extension if provided
    if output_prefix.endswith(".csv"):
        output_prefix = output_prefix[:-4]

    cipher_csv = f"{output_prefix}.csv"
    affected_csv = f"{output_prefix}_affected.csv"
    rich_targets = None
    attempted_xml_files: List[str] = []

    try:
        if args.xml:
            if not Path(args.xml).is_file():
                raise FileNotFoundError(f"XML file not found: {args.xml}")

            print(f"[*] Parsing existing XML: {args.xml}")
            xml_files = [args.xml]
        else:
            if not Path(args.input).is_file():
                raise FileNotFoundError(f"Input file not found: {args.input}")

            input_format = detect_input_format(args.input)
            print(f"[*] Detected input format: {input_format}")

            if input_format in ("rich", "hostport"):
                if input_format == "rich":
                    rich_targets = parse_rich_input(args.input)
                else:
                    rich_targets = parse_hostport_input(args.input)

                if not rich_targets:
                    raise ValueError("no valid targets found in input file")

                print(f"[*] Found {len(rich_targets)} target(s)")
                scan_jobs = build_scan_jobs(rich_targets)
            else:
                if not args.ports:
                    raise ValueError(
                        "-p/--ports is required for simple input format"
                    )

                hosts = parse_simple_input(args.input)
                if not hosts:
                    raise ValueError("no valid hosts found in input file")

                print(f"[*] Found {len(hosts)} unique host(s)")
                scan_jobs = [(args.ports, hosts)]

            xml_files = []
            failed_jobs = []

            with TemporaryDirectory(prefix="tls_auditor_") as temp_dir:
                for job_number, (ports, hosts) in enumerate(scan_jobs, 1):
                    nmap_input = Path(temp_dir) / f"hosts_{job_number}.txt"
                    nmap_input.write_text("\n".join(hosts) + "\n")
                    job_succeeded = False

                    print(
                        f"[*] Scanning port(s) {ports} on {len(hosts)} host(s)"
                    )
                    for round_number in range(1, args.rounds + 1):
                        if len(scan_jobs) > 1 or args.rounds > 1:
                            print(
                                "[*] Starting port(s) "
                                f"{ports}, round {round_number}/{args.rounds}"
                            )

                        round_xml = scan_xml_path(
                            output_prefix,
                            ports,
                            round_number,
                            len(scan_jobs),
                            args.rounds,
                        )
                        attempted_xml_files.append(round_xml)

                        if run_nmap(
                            str(nmap_input),
                            ports,
                            round_xml,
                            args.timing,
                        ):
                            xml_files.append(round_xml)
                            job_succeeded = True
                        else:
                            print(
                                f"[!] Port(s) {ports}, round {round_number} failed",
                                file=sys.stderr,
                            )

                    if not job_succeeded:
                        failed_jobs.append(ports)

            if failed_jobs:
                raise RuntimeError(
                    "no successful scan round for port group(s): "
                    + ", ".join(failed_jobs)
                )

        print("[*] Parsing results...")
        if len(xml_files) > 1:
            results = aggregate_results(xml_files, rich_targets)
        else:
            results = parse_nmap_xml(xml_files[0], rich_targets)

        if not results:
            print("[*] No SSL/TLS services with issues found")
        else:
            print_summary(results)
            write_cipher_csv(results, cipher_csv)
            write_affected_csv(results, affected_csv)

    except (OSError, ET.ParseError, ValueError, RuntimeError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if not args.xml and not args.keep_xml:
            for xml_file in attempted_xml_files:
                Path(xml_file).unlink(missing_ok=True)
        elif not args.xml:
            for xml_file in attempted_xml_files:
                if Path(xml_file).exists():
                    print(f"[*] XML file kept: {xml_file}")

    print("[+] Done")


if __name__ == "__main__":
    main()
