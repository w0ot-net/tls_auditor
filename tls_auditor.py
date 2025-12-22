#!/usr/bin/env python3
"""
SSL/TLS Cipher Security Auditor
Wraps nmap ssl-enum-ciphers and sslv2 scripts to identify insecure TLS configurations.
Requires Python 3.6+
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
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# INSECURE CIPHER DEFINITIONS
# =============================================================================

# Deprecated protocols - report ALL ciphers as insecure
DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0"}

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


# =============================================================================
# INPUT PARSING
# =============================================================================

def parse_rich_input(input_file: str) -> List[Dict[str, str]]:
    """
    Parse rich input format with IP, hostname, and service columns.
    Format: IP<tab>hostname<tab>service (port/tcp)
    """
    targets = []
    
    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Split on tabs or multiple spaces
            parts = re.split(r"\t+|\s{2,}", line)
            
            if len(parts) >= 3:
                ip = parts[0].strip()
                hostname = parts[1].strip()
                service_info = parts[2].strip()
                
                # Extract port from service info like "www (443/tcp)" or "msrdp (3389/tcp)"
                port_match = re.search(r"\((\d+)/tcp\)", service_info)
                if port_match:
                    port = port_match.group(1)
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
    
    return list(set(hosts))  # Deduplicate


def detect_input_format(input_file: str) -> str:
    """Detect whether input file is 'rich' or 'simple' format."""
    with open(input_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Check for tab-separated format with port info
            if "\t" in line or re.search(r"\s{2,}", line):
                if re.search(r"\(\d+/tcp\)", line):
                    return "rich"
            
            return "simple"
    
    return "simple"


def build_nmap_targets(targets: List[Dict[str, str]], temp_file: str) -> Tuple[str, str]:
    """
    Build nmap input file and port list from rich targets.
    Returns (temp_file_path, comma_separated_ports)
    """
    # Collect unique host:port combinations
    host_ports = {}  # ip -> set of ports
    
    for t in targets:
        ip = t["ip"]
        port = t["port"]
        
        if ip not in host_ports:
            host_ports[ip] = set()
        host_ports[ip].add(port)
    
    # Write hosts to temp file
    with open(temp_file, "w") as f:
        for ip in sorted(host_ports.keys()):
            f.write(f"{ip}\n")
    
    # Collect all unique ports
    all_ports = set()
    for ports in host_ports.values():
        all_ports.update(ports)
    
    return temp_file, ",".join(sorted(all_ports, key=int))


# =============================================================================
# NMAP EXECUTION
# =============================================================================

def run_nmap(input_file: str, ports: str, xml_output: str) -> bool:
    """Run nmap with ssl-enum-ciphers and sslv2 scripts."""
    cmd = [
        "nmap",
        "-Pn",
        "-T4",
        "-p", ports,
        "-iL", input_file,
        "--script", "ssl-enum-ciphers,sslv2",
        "-oX", xml_output,
    ]
    
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

def parse_cipher_grade(cipher_line: str) -> Tuple[str, str]:
    """
    Parse cipher name and grade from nmap output.
    Example: "TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A"
    Returns: (cipher_name, grade)
    """
    # Match cipher name and grade
    match = re.match(r"(\S+)\s+.*-\s+([A-F])", cipher_line)
    if match:
        return match.group(1), match.group(2)
    
    # Fallback: just get the cipher name
    parts = cipher_line.split()
    if parts:
        return parts[0], ""
    
    return cipher_line, ""


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


def parse_nmap_xml(xml_file: str, rich_targets: Optional[List[Dict[str, str]]] = None) -> List[Dict]:
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
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] Error parsing XML: {e}", file=sys.stderr)
        return results
    
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
        
        # Get hostname from nmap if available
        nmap_hostname = ""
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                nmap_hostname = hostname_elem.get("name", "")
        
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
            cipher_data = {
                "SSLv2": [],
                "SSLv3": [],
                "TLSv1.0": [],
                "TLSv1.1": [],
                "TLSv1.2": [],
                "TLSv1.3": [],
            }
            
            # Parse ssl-enum-ciphers output
            if ssl_script is not None:
                for table in ssl_script.findall("table"):
                    protocol = table.get("key", "")
                    if protocol not in cipher_data:
                        continue
                    
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
                        
                        if cipher_name and is_cipher_insecure(cipher_name, grade, protocol):
                            cipher_data[protocol].append(cipher_name)
            
            # Parse sslv2 script output
            if sslv2_script is not None:
                output = sslv2_script.get("output", "")
                if "SSLv2 supported" in output:
                    # Extract SSLv2 ciphers
                    for cipher_table in sslv2_script.findall(".//table[@key='ciphers']/table"):
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
            def format_ciphers(ciphers: List[str], protocol: str) -> str:
                if not ciphers:
                    return "-"
                if protocol in DEPRECATED_PROTOCOLS:
                    return "All"
                return ", ".join(sorted(set(ciphers)))
            
            # Check if there are any issues
            has_issues = any(cipher_data[p] for p in cipher_data)
            
            if has_issues:
                results.append({
                    "host_port": f"{host_display}:{port_id}",
                    "SSLv2": format_ciphers(cipher_data["SSLv2"], "SSLv2"),
                    "SSLv3": format_ciphers(cipher_data["SSLv3"], "SSLv3"),
                    "TLSv1.0": format_ciphers(cipher_data["TLSv1.0"], "TLSv1.0"),
                    "TLSv1.1": format_ciphers(cipher_data["TLSv1.1"], "TLSv1.1"),
                    "TLSv1.2": format_ciphers(cipher_data["TLSv1.2"], "TLSv1.2"),
                    "TLSv1.3": format_ciphers(cipher_data["TLSv1.3"], "TLSv1.3"),
                    "ip": ip,
                    "hostname": hostname if hostname else "-",
                    "port": port_id,
                    "service": svc,
                })
    
    return results


# =============================================================================
# OUTPUT GENERATION
# =============================================================================

def write_cipher_csv(results: List[Dict], output_file: str) -> None:
    """Write cipher table to CSV file."""
    fieldnames = ["host_port", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    
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
        print("[*] No SSL/TLS issues found")
        return
    
    print(f"\n[+] Found {len(results)} host(s) with insecure ciphers:")
    
    # Count by protocol
    proto_counts = {
        "SSLv2": 0, "SSLv3": 0, "TLSv1.0": 0,
        "TLSv1.1": 0, "TLSv1.2": 0, "TLSv1.3": 0
    }
    
    for r in results:
        for proto in proto_counts:
            if r.get(proto, "-") != "-":
                proto_counts[proto] += 1
    
    for proto, count in proto_counts.items():
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

  Rich (auto-detects ports):
    172.16.1.10    AD02.example.com    ldaps? (636/tcp)
    172.16.1.41    Web.example.com     www (443/tcp)
    172.16.1.42    -                   https? (443/tcp)

Examples:
  %(prog)s -i hosts.txt -p 443
  %(prog)s -i hosts.txt -p 443,636,3389
  %(prog)s -i rich_targets.txt
  %(prog)s --xml existing_scan.xml -o results.csv
        """
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-i", "--input",
        help="Input file (IP list or rich format with ports)"
    )
    input_group.add_argument(
        "--xml",
        help="Parse existing nmap XML file instead of scanning"
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
        help="Keep the intermediate nmap XML file"
    )
    
    args = parser.parse_args()
    
    # Generate output filename prefix
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = args.output if args.output else f"ssl_audit_{timestamp}"
    
    # Remove .csv extension if provided
    if output_prefix.endswith(".csv"):
        output_prefix = output_prefix[:-4]
    
    cipher_csv = f"{output_prefix}.csv"
    affected_csv = f"{output_prefix}_affected.csv"
    xml_output = f"{output_prefix}.xml"
    
    rich_targets = None
    
    if args.xml:
        # Parse existing XML
        if not Path(args.xml).is_file():
            print(f"[!] Error: XML file not found: {args.xml}", file=sys.stderr)
            sys.exit(1)
        
        print(f"[*] Parsing existing XML: {args.xml}")
        xml_output = args.xml
    
    else:
        # Validate input file
        if not Path(args.input).is_file():
            print(f"[!] Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        
        # Detect input format
        input_format = detect_input_format(args.input)
        print(f"[*] Detected input format: {input_format}")
        
        if input_format == "rich":
            # Parse rich format
            rich_targets = parse_rich_input(args.input)
            if not rich_targets:
                print("[!] Error: No valid targets found in input file", file=sys.stderr)
                sys.exit(1)
            
            print(f"[*] Found {len(rich_targets)} target(s)")
            
            # Build nmap input
            temp_file = f"/tmp/ssl_audit_{timestamp}_hosts.txt"
            nmap_input, ports = build_nmap_targets(rich_targets, temp_file)
            
        else:
            # Simple format - ports required
            if not args.ports:
                print("[!] Error: -p/--ports is required for simple input format", file=sys.stderr)
                sys.exit(1)
            
            hosts = parse_simple_input(args.input)
            if not hosts:
                print("[!] Error: No valid hosts found in input file", file=sys.stderr)
                sys.exit(1)
            
            print(f"[*] Found {len(hosts)} unique host(s)")
            
            # Write deduplicated hosts to temp file
            temp_file = f"/tmp/ssl_audit_{timestamp}_hosts.txt"
            with open(temp_file, "w") as f:
                for host in sorted(hosts):
                    f.write(f"{host}\n")
            
            nmap_input = temp_file
            ports = args.ports
        
        # Run nmap
        print(f"[*] Scanning ports: {ports}")
        
        if not run_nmap(nmap_input, ports, xml_output):
            print("[!] nmap scan failed", file=sys.stderr)
            sys.exit(1)
        
        # Cleanup temp file
        Path(temp_file).unlink(missing_ok=True)
    
    # Parse results
    print("[*] Parsing results...")
    results = parse_nmap_xml(xml_output, rich_targets)
    
    if not results:
        print("[*] No SSL/TLS services with issues found")
    else:
        print_summary(results)
        
        # Write output files
        write_cipher_csv(results, cipher_csv)
        write_affected_csv(results, affected_csv)
    
    # Cleanup XML unless requested to keep (or if parsing existing)
    if not args.keep_xml and not args.xml:
        Path(xml_output).unlink(missing_ok=True)
    elif args.keep_xml:
        print(f"[*] XML file kept: {xml_output}")
    
    print("[+] Done")


if __name__ == "__main__":
    main()