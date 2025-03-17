"""Domain grouping utility functions for suspicious domain analysis."""

import re
import json
import datetime
from typing import Dict, List, Set, Optional, Tuple


def extract_domain_pattern(domain: str) -> str:
    """Extract a pattern from domain name to identify similar domains."""
    # Remove TLD
    base_domain = re.sub(r'\.[a-z]{2,}$', '', domain)
    
    # Extract alphanumeric prefix (ignoring random characters)
    match = re.match(r'^([a-z]+)', base_domain)
    if match and len(match.group(1)) >= 3:
        return match.group(1)
    
    return base_domain


def group_domains_by_pattern(domains: List[str]) -> Dict[str, List[str]]:
    """Group domains by common name patterns."""
    pattern_groups = {}
    
    for domain in domains:
        pattern = extract_domain_pattern(domain)
        if len(pattern) >= 3:  # Only use patterns of reasonable length
            if pattern not in pattern_groups:
                pattern_groups[pattern] = []
            pattern_groups[pattern].append(domain)
    
    # Filter out single-domain groups
    return {k: v for k, v in pattern_groups.items() if len(v) > 1}


def group_domains_by_creation_date(domains: Dict[str, str], window_days: int = 3) -> Dict[str, List[str]]:
    """Group domains by creation date within a specified time window."""
    date_groups = {}
    
    # First pass - create exact date groups
    for domain, date_str in domains.items():
        if date_str not in date_groups:
            date_groups[date_str] = []
        date_groups[date_str].append(domain)
    
    # Second pass - merge groups with dates within window_days of each other
    try:
        dates = sorted(date_groups.keys())
        merged_groups = {}
        current_group_key = dates[0] if dates else None
        current_group = []
        
        for date_str in dates:
            current_date = datetime.datetime.strptime(current_group_key, "%Y-%m-%d")
            this_date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
            
            if (this_date - current_date).days <= window_days:
                # Add to current group
                current_group.extend(date_groups[date_str])
            else:
                # Start a new group
                if current_group:
                    merged_groups[current_group_key] = current_group
                current_group_key = date_str
                current_group = date_groups[date_str].copy()
        
        # Add the last group
        if current_group:
            merged_groups[current_group_key] = current_group
        
        return merged_groups
    except (ValueError, TypeError):
        # If there are date parsing issues, return the original groups
        return {k: v for k, v in date_groups.items() if len(v) > 1}


def calculate_group_overlap(group1: List[str], group2: List[str]) -> float:
    """Calculate the overlap ratio between two domain groups."""
    if not group1 or not group2:
        return 0.0
    
    set1 = set(group1)
    set2 = set(group2)
    intersection = set1.intersection(set2)
    
    if not intersection:
        return 0.0
    
    # Use Jaccard similarity coefficient
    return len(intersection) / len(set1.union(set2))


def merge_overlapping_groups(groups: Dict[str, List[str]], threshold: float = 0.3) -> Dict[str, List[str]]:
    """Merge groups with significant domain overlap."""
    if not groups:
        return {}
    
    # Make a copy of the input to avoid modifying the original
    working_groups = {k: v.copy() for k, v in groups.items()}
    
    while True:
        merged = False
        keys = list(working_groups.keys())
        
        for i in range(len(keys)):
            if i >= len(keys):
                break
                
            key1 = keys[i]
            
            for j in range(i + 1, len(keys)):
                if j >= len(keys):
                    break
                    
                key2 = keys[j]
                overlap = calculate_group_overlap(working_groups[key1], working_groups[key2])
                
                if overlap >= threshold:
                    # Merge groups
                    merged_domains = list(set(working_groups[key1] + working_groups[key2]))
                    working_groups[key1] = merged_domains
                    del working_groups[key2]
                    keys = list(working_groups.keys())  # Update keys list after deletion
                    merged = True
                    break
            
            if merged:
                break
        
        if not merged:
            break
    
    return working_groups


def find_similar_domain_endings(domains: List[str], min_length: int = 3) -> Dict[str, List[str]]:
    """Find domains with similar random-looking endings."""
    suffix_patterns = {}
    
    for domain in domains:
        # Extract suffix pattern (last N characters before TLD)
        match = re.match(r'^[a-z]+([a-z0-9]+)\.[a-z]{2,}$', domain)
        if match and len(match.group(1)) >= min_length:
            suffix = match.group(1).lower()
            if suffix not in suffix_patterns:
                suffix_patterns[suffix] = []
            suffix_patterns[suffix].append(domain)
    
    # Keep only patterns that appear in multiple domains
    return {k: v for k, v in suffix_patterns.items() if len(v) > 1}


def score_domain_suspiciousness(domain: str, creation_date: Optional[str] = None) -> int:
    """Score a domain's suspiciousness based on various factors."""
    score = 0
    
    # Check for random-looking parts in the domain
    if re.search(r'[a-z][0-9]{2,}[a-z]', domain) or re.search(r'[0-9]{2,}[a-z][0-9]', domain):
        score += 2
    
    # Check for unusually long domain names
    parts = domain.split('.')
    if parts and len(parts[0]) > 15:
        score += 1
    
    # Check for domains with random character sequences
    if re.search(r'[a-z][0-9][a-z][0-9]', domain) or re.search(r'[0-9][a-z][0-9][a-z]', domain):
        score += 2
    
    # Check for domains with alternating patterns
    if re.search(r'([a-z][0-9]){2,}', domain) or re.search(r'([0-9][a-z]){2,}', domain):
        score += 2
    
    # Check for domains with uncommon TLDs often used in scams
    if re.search(r'\.(?:cc|icu|xyz|top|club|site|online|space|fun|live|app)$', domain):
        score += 2
    
    # Check for recent creation date (if provided)
    if creation_date:
        try:
            created = datetime.datetime.strptime(creation_date, "%Y-%m-%d")
            today = datetime.datetime.now()
            days_old = (today - created).days
            
            if days_old < 30:  # Less than a month old
                score += 3
            elif days_old < 90:  # Less than three months old
                score += 2
            elif days_old < 180:  # Less than six months old
                score += 1
        except (ValueError, TypeError):
            pass
    
    return score


def identify_campaign_infrastructure(domains_data: List[Dict]) -> Dict[str, List[str]]:
    """Identify domains that share the same infrastructure."""
    # Group by shared nameservers
    ns_groups = {}
    cname_groups = {}
    ip_groups = {}
    
    for domain_data in domains_data:
        domain = domain_data.get("domain")
        if not domain:
            continue
        
        # Check nameservers
        nameservers = domain_data.get("nameservers", []) or domain_data.get("whois_info", {}).get("nameservers", [])
        if nameservers:
            # Group by nameserver pattern
            ns_pattern = nameservers[0].split(".")[0] if nameservers[0] else ""
            if ns_pattern:
                if ns_pattern not in ns_groups:
                    ns_groups[ns_pattern] = []
                ns_groups[ns_pattern].append(domain)
        
        # Check CNAME records
        dns_records = domain_data.get("dns_records", {})
        cname_records = dns_records.get("CNAME", []) if isinstance(dns_records, dict) else []
        if cname_records:
            cname = cname_records[0]
            if cname not in cname_groups:
                cname_groups[cname] = []
            cname_groups[cname].append(domain)
        
        # Check IP addresses
        ip_addresses = domain_data.get("main_ip_addresses", [])
        for ip in ip_addresses:
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(domain)
    
    # Filter to include only groups with multiple domains
    ns_groups = {k: v for k, v in ns_groups.items() if len(v) > 1}
    cname_groups = {k: v for k, v in cname_groups.items() if len(v) > 1}
    ip_groups = {k: v for k, v in ip_groups.items() if len(v) > 1}
    
    return {
        "nameserver_groups": ns_groups,
        "cname_groups": cname_groups, 
        "ip_groups": ip_groups
    }