#!/usr/bin/env python
"""
Generate lists of suspicious domains based on various indicators.

This script analyzes the evidence data, screenshot similarity analysis, and investigation
results to identify and group suspicious domains for reporting purposes.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Any, Tuple, TypeVar

# Define type variables
T = TypeVar('T')

from scamrecon.reporters.utils.domain_grouping import (
    group_domains_by_pattern,
    group_domains_by_creation_date,
    merge_overlapping_groups,
    identify_campaign_infrastructure,
    score_domain_suspiciousness
)


def load_data(results_dir: str, screenshot_groups_dir: str, evidence_dir: str) -> Dict:
    """
    Load all relevant data from various sources.
    
    Args:
        results_dir: Directory containing investigation results
        screenshot_groups_dir: Directory containing screenshot similarity analysis
        evidence_dir: Directory containing evidence files
        
    Returns:
        Dictionary containing all loaded data
    """
    data = {
        "investigations": [],
        "screenshot_groups": {},
        "domain_creation_dates": {},
        "domain_infrastructure": defaultdict(dict),
        "evidence": {}
    }
    
    # Load screenshot similarity data
    screenshot_analysis_path = os.path.join(screenshot_groups_dir, "screenshot-analysis-report.json")
    if os.path.exists(screenshot_analysis_path):
        try:
            with open(screenshot_analysis_path, 'r') as f:
                screenshot_data = json.load(f)
                data["screenshot_groups"] = {group["group_id"]: group for group in screenshot_data.get("groups", [])}
                print(f"Loaded screenshot analysis with {len(data['screenshot_groups'])} visual similarity groups")
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading screenshot analysis: {e}")
    
    # Load registration timeline data
    novelty_analysis_path = os.path.join(screenshot_groups_dir, "novelty-analysis.json")
    if os.path.exists(novelty_analysis_path):
        try:
            with open(novelty_analysis_path, 'r') as f:
                novelty_data = json.load(f)
                for entry in novelty_data.get("registration_timeline", []):
                    date_str = entry.get("date")
                    if date_str and date_str != "Unknown":
                        for domain in entry.get("domains", []):
                            # Remove trailing underscore if present (from screenshot naming)
                            clean_domain = domain.rstrip('_')
                            data["domain_creation_dates"][clean_domain] = date_str
                            
                            # Store infrastructure data
                            infra = entry.get("infrastructure", {})
                            if infra:
                                data["domain_infrastructure"][clean_domain]["nameserver_patterns"] = infra.get("nameserver_patterns", [])
                                data["domain_infrastructure"][clean_domain]["cname_records"] = infra.get("cname_records", [])
            print(f"Loaded creation dates for {len(data['domain_creation_dates'])} domains")
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading novelty analysis: {e}")
    
    # Load domain investigation data
    investigation_count = 0
    for filename in os.listdir(results_dir):
        if filename.endswith("_investigation.json"):
            investigation_path = os.path.join(results_dir, filename)
            try:
                with open(investigation_path, 'r') as f:
                    investigation_data = json.load(f)
                    data["investigations"].append(investigation_data)
                    investigation_count += 1
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading investigation file {investigation_path}: {e}")
    print(f"Loaded {investigation_count} domain investigation files")
    
    # Load Cloudflare report data
    evidence_count = 0
    for filename in os.listdir(evidence_dir):
        if filename.endswith("_cloudflare_report.json"):
            evidence_path = os.path.join(evidence_dir, filename)
            try:
                with open(evidence_path, 'r') as f:
                    evidence_data = json.load(f)
                    domain = evidence_data.get("domain")
                    if domain:
                        data["evidence"][domain] = evidence_data
                        evidence_count += 1
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading evidence file {evidence_path}: {e}")
    print(f"Loaded {evidence_count} evidence files")
    
    return data


def analyze_suspicious_domains(data: Dict) -> Dict:
    """
    Analyze the data to identify suspicious domains and group them.
    
    Args:
        data: Dictionary containing all loaded data
        
    Returns:
        Dictionary containing analysis results
    """
    results = {
        "screenshot_similarity_groups": [],
        "infrastructure_groups": {},
        "pattern_groups": {},
        "creation_date_groups": {},
        "combined_suspicious_groups": [],
        "high_risk_domains": []
    }
    
    # Process visual similarity groups
    for group_id, group_data in data["screenshot_groups"].items():
        if group_data.get("count", 0) <= 1:
            continue  # Skip single-domain groups
            
        # Clean domain names (remove trailing underscores)
        domains = [domain.rstrip('_') for domain in group_data.get("domains", [])]
        if len(domains) > 1:
            results["screenshot_similarity_groups"].append({
                "group_id": group_id,
                "domains": domains,
                "count": len(domains)
            })
    
    # Process domain name pattern groups
    all_domains = list(set([inv.get("domain") for inv in data["investigations"] if inv.get("domain")]))
    results["pattern_groups"] = group_domains_by_pattern(all_domains)
    
    # Process creation date groups
    results["creation_date_groups"] = group_domains_by_creation_date(data["domain_creation_dates"], window_days=3)
    
    # Process infrastructure groups
    results["infrastructure_groups"] = identify_campaign_infrastructure(data["investigations"])
    
    # Score domains for suspiciousness
    domain_scores = {}
    for domain in all_domains:
        creation_date = data["domain_creation_dates"].get(domain)
        domain_scores[domain] = score_domain_suspiciousness(domain, creation_date)
    
    # Identify high-risk domains (score >= 5)
    results["high_risk_domains"] = [domain for domain, score in domain_scores.items() if score >= 5]
    
    # Create combined suspicious groups
    # Start with visual similarity groups
    suspicious_groups = []
    processed_domains = set()
    
    # Use visual similarity groups as seeds
    for group in results["screenshot_similarity_groups"]:
        domain_set = set(group["domains"])
        if not domain_set - processed_domains:  # Skip if all domains already processed
            continue
            
        group_data = {
            "domains": list(domain_set),
            "indicators": ["visual_similarity"],
            "screenshot_group_id": group["group_id"],
            "visual_similarity_count": len(domain_set),
            "infrastructure_similarity": False,
            "name_pattern_similarity": False,
            "creation_date_proximity": False
        }
        
        # Check for infrastructure similarity
        shared_ns = False
        shared_cname = False
        shared_ip = False
        
        # Check nameserver groups
        for ns_pattern, domains in results["infrastructure_groups"]["nameserver_groups"].items():
            if domain_set.intersection(set(domains)):
                shared_ns = True
                break
                
        # Check CNAME groups
        for cname, domains in results["infrastructure_groups"]["cname_groups"].items():
            if domain_set.intersection(set(domains)):
                shared_cname = True
                break
                
        # Check IP groups
        for ip, domains in results["infrastructure_groups"]["ip_groups"].items():
            if domain_set.intersection(set(domains)):
                shared_ip = True
                break
                
        if shared_ns or shared_cname or shared_ip:
            group_data["infrastructure_similarity"] = True
            group_data["indicators"].append("infrastructure")
        
        # Check for name pattern similarity
        for pattern, domains in results["pattern_groups"].items():
            if domain_set.intersection(set(domains)):
                group_data["name_pattern_similarity"] = True
                group_data["indicators"].append("name_pattern")
                break
        
        # Check for creation date proximity
        for date, domains in results["creation_date_groups"].items():
            if domain_set.intersection(set(domains)):
                group_data["creation_date_proximity"] = True
                group_data["indicators"].append("creation_date")
                group_data["creation_date"] = date
                break
        
        # Add high-risk domains to the indicators
        high_risk_count = len(domain_set.intersection(set(results["high_risk_domains"])))
        if high_risk_count > 0:
            group_data["high_risk_count"] = high_risk_count
            group_data["indicators"].append("high_risk_score")
        
        suspicious_groups.append(group_data)
        processed_domains.update(domain_set)
    
    # Next, process domains from infrastructure groups that haven't been processed yet
    for group_type, groups in results["infrastructure_groups"].items():
        for identifier, domains in groups.items():
            domain_set = set(domains)
            if not domain_set - processed_domains:  # Skip if all domains already processed
                continue
                
            unprocessed_domains = domain_set - processed_domains
            if len(unprocessed_domains) > 1:  # Only create a group if there are multiple unprocessed domains
                group_data = {
                    "domains": list(unprocessed_domains),
                    "indicators": ["infrastructure"],
                    "infrastructure_similarity": True,
                    "infrastructure_type": group_type,
                    "infrastructure_id": identifier,
                    "visual_similarity_count": 0,
                    "name_pattern_similarity": False,
                    "creation_date_proximity": False
                }
                
                # Check for name pattern similarity
                for pattern, pattern_domains in results["pattern_groups"].items():
                    if unprocessed_domains.intersection(set(pattern_domains)):
                        group_data["name_pattern_similarity"] = True
                        group_data["indicators"].append("name_pattern")
                        break
                
                # Check for creation date proximity
                for date, date_domains in results["creation_date_groups"].items():
                    if unprocessed_domains.intersection(set(date_domains)):
                        group_data["creation_date_proximity"] = True
                        group_data["indicators"].append("creation_date")
                        group_data["creation_date"] = date
                        break
                
                # Add high-risk domains to the indicators
                high_risk_count = len(unprocessed_domains.intersection(set(results["high_risk_domains"])))
                if high_risk_count > 0:
                    group_data["high_risk_count"] = high_risk_count
                    group_data["indicators"].append("high_risk_score")
                
                suspicious_groups.append(group_data)
                processed_domains.update(unprocessed_domains)
    
    # Process domains with high risk scores that haven't been grouped yet
    remaining_high_risk = set(results["high_risk_domains"]) - processed_domains
    if remaining_high_risk:
        group_data = {
            "domains": list(remaining_high_risk),
            "indicators": ["high_risk_score"],
            "high_risk_count": len(remaining_high_risk),
            "visual_similarity_count": 0,
            "infrastructure_similarity": False,
            "name_pattern_similarity": False,
            "creation_date_proximity": False
        }
        suspicious_groups.append(group_data)
        processed_domains.update(remaining_high_risk)
    
    # Sort groups by number of indicators then by domain count
    results["combined_suspicious_groups"] = sorted(
        suspicious_groups,
        key=lambda x: (len(x["indicators"]), len(x["domains"])),
        reverse=True
    )
    
    # Add group IDs
    for i, group in enumerate(results["combined_suspicious_groups"]):
        group["group_id"] = i + 1
    
    return results


def save_suspicious_domain_lists(results: Dict, output_dir: str) -> None:
    """
    Save the analysis results to output files.
    
    Args:
        results: The analysis results
        output_dir: Directory to save output files
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Save the complete analysis results
    with open(os.path.join(output_dir, "suspicious_domains_analysis.json"), 'w') as f:
        json.dump({
            "generated_at": datetime.now().isoformat(),
            "screenshot_similarity_groups": results["screenshot_similarity_groups"],
            "infrastructure_groups": results["infrastructure_groups"],
            "pattern_groups": results["pattern_groups"],
            "creation_date_groups": results["creation_date_groups"],
            "high_risk_domains": results["high_risk_domains"],
            "combined_suspicious_groups": results["combined_suspicious_groups"]
        }, f, indent=2)
    
    # Save list of high-risk domains
    with open(os.path.join(output_dir, "high_risk_domains.txt"), 'w') as f:
        for domain in sorted(results["high_risk_domains"]):
            f.write(f"{domain}\n")
    
    # Save domain lists for each suspicious group
    for group in results["combined_suspicious_groups"]:
        group_id = group["group_id"]
        with open(os.path.join(output_dir, f"suspicious_group_{group_id}.txt"), 'w') as f:
            for domain in sorted(group["domains"]):
                f.write(f"{domain}\n")
    
    # Create a summary report in Markdown format
    with open(os.path.join(output_dir, "suspicious_domains_summary.md"), 'w') as f:
        f.write("# Suspicious Domains Analysis Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Summary Statistics\n\n")
        f.write(f"- Total suspicious groups identified: {len(results['combined_suspicious_groups'])}\n")
        f.write(f"- High-risk domains identified: {len(results['high_risk_domains'])}\n")
        f.write(f"- Visual similarity groups: {len(results['screenshot_similarity_groups'])}\n")
        
        total_domains = set()
        for group in results["combined_suspicious_groups"]:
            total_domains.update(group["domains"])
        f.write(f"- Total unique suspicious domains: {len(total_domains)}\n\n")
        
        f.write("## Top Suspicious Groups\n\n")
        for group in results["combined_suspicious_groups"][:5]:  # Show top 5 groups
            f.write(f"### Group {group['group_id']} - {len(group['domains'])} domains\n\n")
            f.write("**Indicators:**\n")
            for indicator in group["indicators"]:
                f.write(f"- {indicator}\n")
            f.write("\n**Domains:**\n")
            for domain in sorted(group["domains"])[:10]:  # Show up to 10 domains per group
                f.write(f"- {domain}\n")
            if len(group["domains"]) > 10:
                f.write(f"- ... and {len(group['domains']) - 10} more\n")
            f.write("\n")
        
        f.write("## Generated Files\n\n")
        f.write("- `suspicious_domains_analysis.json`: Complete analysis data\n")
        f.write("- `high_risk_domains.txt`: List of domains with high risk scores\n")
        for group in results["combined_suspicious_groups"]:
            f.write(f"- `suspicious_group_{group['group_id']}.txt`: Domains in suspicious group #{group['group_id']}\n")
    
    print(f"\nAnalysis complete. Results saved to {output_dir}")
    print(f"Found {len(results['combined_suspicious_groups'])} suspicious domain groups")
    print(f"Identified {len(results['high_risk_domains'])} high-risk domains")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Generate lists of suspicious domains based on various indicators")
    parser.add_argument(
        "--results", 
        default="./results",
        help="Directory containing investigation result files")
    parser.add_argument(
        "--screenshots", 
        default="./screenshot_groups",
        help="Directory containing screenshot analysis files")
    parser.add_argument(
        "--evidence", 
        default="./evidence",
        help="Directory containing evidence files")
    parser.add_argument(
        "--output", 
        default="./reports/suspicious_domains",
        help="Directory to save output files")
    
    args = parser.parse_args()
    
    # Check if directories exist
    for path, name in [(args.results, "Results"), (args.screenshots, "Screenshots"), (args.evidence, "Evidence")]:
        if not os.path.exists(path):
            print(f"Error: {name} directory not found: {path}")
            return 1
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Load all data
    print("Loading data...")
    data = load_data(args.results, args.screenshots, args.evidence)
    
    # Analyze the data
    print("\nAnalyzing suspicious domains...")
    results = analyze_suspicious_domains(data)
    
    # Save the results
    save_suspicious_domain_lists(results, args.output)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())