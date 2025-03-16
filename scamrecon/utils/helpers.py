"""
General utility functions used across the application.
"""

import os
import re
from typing import List, Optional, Set
from urllib.parse import urlparse

# Cloudflare IP ranges (simplified version)
CLOUDFLARE_IP_PREFIXES = [
    "103.21.244.",
    "103.22.200.",
    "103.31.4.",
    "104.16.",
    "104.17.",
    "104.18.",
    "108.162.192.",
    "141.101.64.",
    "162.158.",
    "172.64.",
    "173.245.48.",
    "190.93.240.",
    "197.234.240.",
    "198.41.128.",
]


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain string by removing http/https and trailing slashes.

    Args:
        domain: Domain name or URL to normalize

    Returns:
        Normalized domain name
    """
    domain = domain.lower().strip()

    # Remove protocol and path if present
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc

    # Remove trailing slash if present
    domain = domain.rstrip("/")

    return domain


def is_valid_domain(domain: str) -> bool:
    """
    Check if a string is a valid domain.

    Args:
        domain: Domain name to validate

    Returns:
        True if valid domain, False otherwise
    """
    domain_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}"
    return bool(re.match(domain_pattern, domain))


def is_cloudflare_ip(ip: str) -> bool:
    """
    Check if an IP belongs to Cloudflare's known ranges.

    Args:
        ip: IP address to check

    Returns:
        True if IP belongs to Cloudflare, False otherwise
    """
    try:
        return any(ip.startswith(prefix) for prefix in CLOUDFLARE_IP_PREFIXES)
    except Exception:
        return False


def extract_ips_from_text(text: str) -> Set[str]:
    """
    Extract IP addresses from a text string.

    Args:
        text: Text to extract IPs from

    Returns:
        Set of IP addresses
    """
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    return set(re.findall(ip_pattern, text))


def resolve_domain(domain: str, record_type: str = "A", timeout: int = 10) -> List[str]:
    """
    Resolve domain DNS records and return results as a list.

    Args:
        domain: Domain to resolve
        record_type: DNS record type (A, AAAA, MX, etc.)
        timeout: Timeout in seconds

    Returns:
        List of resolved records as strings
    """
    import dns.resolver

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.Timeout:
        return []
    except Exception:
        return []


def get_headers(url: str, timeout: int = 10, user_agent: Optional[str] = None) -> dict:
    """
    Get HTTP headers for a URL.

    Args:
        url: URL to fetch headers from
        timeout: Timeout in seconds
        user_agent: Optional user agent string

    Returns:
        Dictionary with status code and headers
    """
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    try:
        headers = {}
        if user_agent:
            headers["User-Agent"] = user_agent

        response = requests.head(
            url, timeout=timeout, verify=False, allow_redirects=True, headers=headers
        )

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def load_domains_from_file(domains_file: str) -> List[str]:
    """Load domains from a CSV or TXT file."""
    domains = []
    file_ext = os.path.splitext(domains_file)[1].lower()

    if file_ext == ".csv":
        # Load from CSV
        with open(domains_file, "r") as f:
            content = f.read()
            if "," in content.split("\n")[0]:  # Check if it's comma-separated
                # Split by lines and process each line
                lines = content.strip().split("\n")
                for i, line in enumerate(lines):
                    if i == 0:  # Skip header
                        continue
                    parts = line.split(",")
                    if parts and len(parts) > 0:
                        domain = (
                            parts[1].strip() if len(parts) > 1 else parts[0].strip()
                        )
                        if domain:
                            domains.append(domain)
            else:
                # If it's not comma-separated, treat as single column
                lines = content.strip().split("\n")
                for i, line in enumerate(lines):
                    if i == 0:  # Skip header
                        continue
                    domain = line.strip()
                    if domain:
                        domains.append(domain)
    else:
        # Load from TXT
        with open(domains_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]

    return domains

