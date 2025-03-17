"""
Utilities for domain processing and management.
"""

import csv
import os
import re
import socket
from typing import Dict, List, Optional, Set, Tuple, Union

import dns.resolver


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain name by removing protocols, paths, and trailing slashes.
    
    Args:
        domain: Domain name to normalize
        
    Returns:
        str: Normalized domain name
    """
    # Remove protocol
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    
    # Remove path and query parameters
    domain = domain.split("/", 1)[0]
    domain = domain.split("?", 1)[0]
    
    # Remove port
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    
    # Strip whitespace
    return domain.strip().lower()


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain name.
    
    Args:
        domain: Domain name to check
        
    Returns:
        bool: True if valid domain, False otherwise
    """
    if not domain:
        return False
        
    # Normalize domain first
    domain = normalize_domain(domain)
    
    # Basic regex for domain validation
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
    
    return bool(re.match(domain_pattern, domain))


def resolve_domain(
    domain: str, 
    record_type: str = "A", 
    timeout: int = 10,
    nameserver: Optional[str] = None
) -> List[str]:
    """
    Resolve a domain name to IP addresses or other DNS records.
    
    Args:
        domain: Domain name to resolve
        record_type: DNS record type to query (A, AAAA, MX, etc.)
        timeout: Timeout in seconds
        nameserver: Optional custom nameserver to use
        
    Returns:
        List[str]: List of resolved records
    """
    try:
        # Create resolver with custom settings
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        if nameserver:
            resolver.nameservers = [nameserver]
        
        # Perform the query
        answers = resolver.resolve(domain, record_type)
        
        # Format results based on record type
        results = []
        
        for answer in answers:
            if record_type == "A" or record_type == "AAAA":
                results.append(str(answer))
            elif record_type == "MX":
                # For MX records, include priority
                results.append(f"{answer.preference} {answer.exchange}")
            elif record_type == "TXT":
                # For TXT records, convert to string
                results.append(str(answer).strip('"'))
            else:
                # Default formatting for other record types
                results.append(str(answer))
                
        return results
        
    except dns.resolver.NXDOMAIN:
        # Domain does not exist
        return []
    except dns.resolver.NoAnswer:
        # No records of the requested type
        return []
    except dns.resolver.Timeout:
        # Query timed out
        return []
    except Exception as e:
        # Any other error
        print(f"Error resolving {domain} ({record_type}): {str(e)}")
        return []


def is_cloudflare_ip(ip: str) -> bool:
    """
    Check if an IP address belongs to Cloudflare.
    
    Args:
        ip: IP address to check
        
    Returns:
        bool: True if IP belongs to Cloudflare, False otherwise
    """
    # Known Cloudflare IP ranges
    cloudflare_ranges = [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
    ]
    
    # Convert IP to integer for range comparison
    def ip_to_int(ip_addr):
        octets = ip_addr.split('.')
        return (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])
    
    # Check if IP is in a CIDR range
    def is_ip_in_range(ip_addr, cidr):
        ip_range, bits = cidr.split('/')
        ip_int = ip_to_int(ip_addr)
        range_int = ip_to_int(ip_range)
        mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
        return (ip_int & mask) == (range_int & mask)
    
    # Check each Cloudflare range
    try:
        for cf_range in cloudflare_ranges:
            if is_ip_in_range(ip, cf_range):
                return True
        return False
    except Exception:
        # In case of any error, assume not Cloudflare
        return False


def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract IP addresses from text content.
    
    Args:
        text: Text content to search
        
    Returns:
        List[str]: List of extracted IP addresses
    """
    # IPv4 pattern
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    
    # Find all matches
    matches = re.findall(ip_pattern, text)
    
    # Filter valid IP addresses
    valid_ips = []
    for ip in matches:
        # Basic validation
        try:
            octets = ip.split(".")
            if len(octets) == 4 and all(0 <= int(octet) <= 255 for octet in octets):
                valid_ips.append(ip)
        except ValueError:
            pass
            
    return valid_ips


def load_domains_from_file(file_path: str, skip_lines: int = 0) -> List[str]:
    """
    Load domain names from a CSV or TXT file.
    
    Args:
        file_path: Path to the file containing domains
        skip_lines: Number of lines to skip from the beginning
        
    Returns:
        List[str]: List of normalized domain names
    """
    domains = []
    file_ext = os.path.splitext(file_path)[1].lower()
    
    try:
        if file_ext == ".csv":
            # Try to load as CSV first
            with open(file_path, "r") as f:
                reader = csv.reader(f)
                
                # Skip header and additional lines if needed
                for _ in range(skip_lines):
                    next(reader, None)
                
                for row in reader:
                    if not row:
                        continue
                        
                    # Try to get domain from second column (index 1) first
                    domain = row[1].strip() if len(row) > 1 else row[0].strip()
                    
                    if domain and is_valid_domain(domain):
                        domains.append(normalize_domain(domain))
        else:
            # Load as plain text
            with open(file_path, "r") as f:
                lines = f.readlines()[skip_lines:]
                
                for line in lines:
                    domain = line.strip()
                    if domain and is_valid_domain(domain):
                        domains.append(normalize_domain(domain))
                        
        return domains
        
    except Exception as e:
        print(f"Error loading domains from {file_path}: {str(e)}")
        return []