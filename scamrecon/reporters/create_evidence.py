"""
Abuse Report Generator

This script generates structured abuse reports for phishing/scam domains
based on technical investigation data.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

# Reporter data - can be configured as needed
DEFAULT_REPORTER = {
    "name": "Cookie",
    "email": "slaymeacookie@gmail.com",
    "title": "Security Analyst",
    "company": "HackBack",
    "include_contact_info": True,
}


def generate_abuse_report(
    investigation_data: Dict,
    report_type: str,
    additional_evidence: Dict = None,
    screenshot_analysis: Dict = None,
) -> Dict:
    """
    Generate a structured abuse report from investigation data

    Args:
        investigation_data: The domain investigation data
        report_type: The type of report (registrar, hosting, cloudflare)
        additional_evidence: Optional additional evidence to include
        screenshot_analysis: Optional screenshot analysis data

    Returns:
        Formatted abuse report dictionary
    """
    if additional_evidence is None:
        additional_evidence = {}

    domain = investigation_data.get("domain")

    # Handle domains with unknown creation date
    creation_date_str = investigation_data.get("whois_info", {}).get(
        "creation_date", ""
    )
    if not creation_date_str or creation_date_str == "Unknown":
        # Set a fallback date for unknown creation dates (30 days ago)
        creation_date = datetime.now(timezone.utc) - timedelta(days=30)
        domain_age = 30  # Default to 30 days
    else:
        try:
            creation_date = datetime.fromisoformat(
                creation_date_str.replace("Z", "+00:00")
            )
            current_date = datetime.now(timezone.utc)
            domain_age = (current_date - creation_date).days  # in days
        except ValueError:
            # Handle unparseable dates
            creation_date = datetime.now(timezone.utc) - timedelta(days=30)
            domain_age = 30  # Default to 30 days

    # Get visual similarity group info if available
    visual_group_id = None
    visually_similar_domains = []
    screenshot_sim_dir = None

    if screenshot_analysis and domain:
        visual_group_id, visually_similar_domains = get_screenshot_group_for_domain(
            domain, screenshot_analysis
        )
        # Add visual similarity domains to the related domains if they exist
        if visually_similar_domains:
            current_related = additional_evidence.get("related_domains", [])
            combined_domains = list(set(current_related + visually_similar_domains))
            additional_evidence["related_domains"] = combined_domains
            additional_evidence["screenshots"] = True
            additional_evidence["visual_group_id"] = visual_group_id

            # Add path to screenshot group directory for evidence
            if visual_group_id is not None:
                base_dir = os.path.join(
                    os.path.dirname(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    ),
                    "screenshot_groups",
                )

                # Look for the screenshot group directory
                group_dir = os.path.join(base_dir, "groups", f"group_{visual_group_id}")

                if os.path.exists(group_dir):
                    screenshot_sim_dir = group_dir
                    additional_evidence["screenshot_sim_dir"] = screenshot_sim_dir

    # Create a consolidated justification that includes all important technical details
    justification = f'The domain "{domain}" is hosting a phishing/task/crypto scam that begins impersonating legitimate recruitement service. '

    # Add domain registration data
    justification += f"This domain was registered on {creation_date.date().isoformat()} ({domain_age} days ago). "

    # Add technical details based on report type in a concise way
    if report_type == "cloudflare":
        cname = investigation_data.get("dns_records", {}).get("CNAME", ["N/A"])[0]
        ips = ", ".join(investigation_data.get("main_ip_addresses", []))
        justification += f"Site uses CloudFlare protection with CNAME {cname}. "

    # Add nameserver info
    nameservers = investigation_data.get("whois_info", {}).get("nameservers", [])
    if nameservers:
        justification += f"Site uses nameservers: {', '.join(nameservers[:2])}. "

    # Add related domains concisely if available
    related_domains = additional_evidence.get("related_domains", [])
    if related_domains and len(related_domains) > 0:
        justification += (
            f"Related scam domains include: {', '.join(related_domains[:5])}. "
        )

    # Add visual similarity information if available
    if visual_group_id is not None and visually_similar_domains:
        justification += f"Our visual similarity analysis has identified this domain as part of Group {visual_group_id}, which includes {len(visually_similar_domains) + 1} domains with identical or nearly identical page layouts. "

    # Add user impact
    justification += "Several users have contacted the impersonated firms with complaints of losing money to sites in this network. "
    justification += "The network has begun operating very recently. "

    # Add URLScan link if available
    if additional_evidence.get("urlscan_link"):
        justification += f"Please find additional evidence on {additional_evidence.get('urlscan_link')}"
    else:
        justification += "Please find additional evidence on https://webel.github.io/scamwatch[#domain-url]"

    # Keep a minimal comment since we've moved most info to justification
    comments = f"This site was observed as part of a campaign that began beginning of March, 2025."

    # Build the complete report
    abuse_report = {
        "name": DEFAULT_REPORTER["name"],
        "email": DEFAULT_REPORTER["email"],
        "title": DEFAULT_REPORTER["title"],
        "company": DEFAULT_REPORTER["company"],
        "domain": domain,
        "report_type": report_type,
        "justification": justification,
        "comments": comments,
        "include_contact_info": DEFAULT_REPORTER["include_contact_info"],
        "technical_evidence": {
            "domain_age_days": domain_age,
            "creation_date": investigation_data.get("whois_info", {}).get(
                "creation_date"
            ),
            "ip_addresses": investigation_data.get("main_ip_addresses", []),
            "is_cloudflare": investigation_data.get("is_cloudflare_protected", False),
            "cname_records": investigation_data.get("dns_records", {}).get("CNAME", []),
            "nameservers": investigation_data.get("nameservers", [])
            or investigation_data.get("whois_info", {}).get("nameservers", []),
            "urlscan_link": investigation_data.get("urlscan", {}).get("result_url", ""),
        },
    }

    # Add screenshot analysis data if available
    if visual_group_id is not None:
        abuse_report["technical_evidence"]["visual_similarity"] = {
            "group_id": visual_group_id,
            "similar_domains": visually_similar_domains,
            "analysis_timestamp": screenshot_analysis.get("timestamp"),
        }

        # Include screenshot similarity directory if available
        if screenshot_sim_dir:
            abuse_report["technical_evidence"]["visual_similarity"][
                "screenshot_sim_dir"
            ] = screenshot_sim_dir

            # Find composite image if it exists
            composite_image = os.path.join(
                screenshot_sim_dir, f"group_{visual_group_id}_composite.png"
            )
            if os.path.exists(composite_image):
                abuse_report["technical_evidence"]["visual_similarity"][
                    "composite_image"
                ] = composite_image

            # Get list of all screenshots in this group directory
            if os.path.exists(screenshot_sim_dir):
                screenshot_files = [
                    f
                    for f in os.listdir(screenshot_sim_dir)
                    if f.endswith(".png") and not f.startswith("group_")
                ]
                abuse_report["technical_evidence"]["visual_similarity"][
                    "screenshot_files"
                ] = screenshot_files

    return abuse_report


def get_last_modified_date(investigation_data: Dict) -> str:
    """
    Extract the last modified date from HTTP headers

    Args:
        investigation_data: The domain investigation data

    Returns:
        Last modified date or "unknown date" if not available
    """
    try:
        http_headers = investigation_data.get("http_headers", {})
        https_headers = http_headers.get("https", {}).get("headers", {})
        http_headers_basic = http_headers.get("http", {}).get("headers", {})

        last_modified = https_headers.get("Last-Modified") or http_headers_basic.get(
            "Last-Modified"
        )
        return last_modified or "unknown date"
    except Exception:
        return "unknown date"


def identify_campaigns(investigations: List[Dict]) -> Dict:
    """
    Identify domains that are part of the same campaign based on shared infrastructure

    Args:
        investigations: List of domain investigation objects

    Returns:
        Dictionary of campaigns grouped by infrastructure signatures
    """
    campaigns = {}

    for investigation in investigations:
        # Create a signature based on common infrastructure elements
        cname = (
            investigation.get("dns_records", {}).get("CNAME", ["unknown"])[0]
            if investigation.get("dns_records", {}).get("CNAME")
            else "unknown"
        )
        ips = ",".join(investigation.get("main_ip_addresses", [])) or "unknown"
        nameserver_pattern = (
            investigation.get("whois_info", {})
            .get("nameservers", ["unknown"])[0]
            .split(".")[0]
            if investigation.get("whois_info", {}).get("nameservers")
            else "unknown"
        )

        signature = f"{cname}-{ips}-{nameserver_pattern}"

        # Safe date parsing function
        def safe_parse_date(date_str):
            if not date_str or date_str == "Unknown":
                return datetime.now(timezone.utc) - timedelta(days=30)
            try:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            except ValueError:
                return datetime.now(timezone.utc) - timedelta(days=30)

        # Get creation date safely
        creation_date_str = investigation.get("whois_info", {}).get("creation_date", "")
        creation_date = safe_parse_date(creation_date_str)

        if signature not in campaigns:
            campaigns[signature] = {
                "domains": [],
                "cname": cname,
                "ips": investigation.get("main_ip_addresses", []),
                "nameserver_pattern": nameserver_pattern,
                "date_range": {
                    "earliest": creation_date,
                    "latest": creation_date,
                },
            }

        # Add domain to campaign
        campaigns[signature]["domains"].append(investigation.get("domain"))

        # Update date range if needed
        if creation_date < campaigns[signature]["date_range"]["earliest"]:
            campaigns[signature]["date_range"]["earliest"] = creation_date
        if creation_date > campaigns[signature]["date_range"]["latest"]:
            campaigns[signature]["date_range"]["latest"] = creation_date

    return campaigns


def generate_campaign_summary(investigations: List[Dict]) -> Dict:
    """
    Generate a summary report of a phishing campaign

    Args:
        investigations: List of domain investigation objects

    Returns:
        Campaign summary report dictionary
    """
    campaigns = identify_campaigns(investigations)

    # Get the largest campaign
    largest_campaign = None
    max_domains = 0

    for signature, campaign in campaigns.items():
        if len(campaign["domains"]) > max_domains:
            largest_campaign = campaign
            max_domains = len(campaign["domains"])

    if not largest_campaign:
        return {"error": "No campaigns identified"}

    # Format date range
    def format_date(date):
        return date.date().isoformat()

    # Create campaign summary
    summary = {
        "campaign_size": len(largest_campaign["domains"]),
        "domains": largest_campaign["domains"],
        "infrastructure": {
            "cname": largest_campaign["cname"],
            "ips": largest_campaign["ips"],
            "nameserver_pattern": largest_campaign["nameserver_pattern"],
        },
        "date_range": {
            "start": format_date(largest_campaign["date_range"]["earliest"]),
            "end": format_date(largest_campaign["date_range"]["latest"]),
        },
        "report_generation_date": format_date(datetime.now(timezone.utc)),
    }

    return summary


def generate_registrar_report(
    investigation: Dict,
    all_investigations: List[Dict],
    screenshot_analysis: Dict = None,
) -> Dict:
    """
    Generate a report for registrar abuse department

    Args:
        investigation: Domain investigation data
        all_investigations: All domain investigations for context
        screenshot_analysis: Optional screenshot analysis data
        enhanced_screenshot_data: Optional enhanced screenshot data

    Returns:
        Formatted registrar abuse report
    """
    campaigns = identify_campaigns(all_investigations)

    # Find which campaign this domain belongs to
    related_domains = []
    for signature, campaign in campaigns.items():
        if investigation.get("domain") in campaign["domains"]:
            related_domains = [
                d for d in campaign["domains"] if d != investigation.get("domain")
            ]
            break

    return generate_abuse_report(
        investigation,
        "registrar",
        {
            "related_domains": related_domains[:5],  # Include up to 5 related domains
            "urlscan_link": investigation.get("urlscan", {}).get("result_url"),
            "screenshots": False,
        },
        screenshot_analysis,
    )


def generate_cloudflare_report(
    investigation: Dict,
    all_investigations: List[Dict],
    screenshot_analysis: Dict = None,
) -> Dict:
    """
    Generate a report for CloudFlare abuse department

    Args:
        investigation: Domain investigation data
        all_investigations: All domain investigations for context
        screenshot_analysis: Optional screenshot analysis data
        enhanced_screenshot_data: Optional enhanced screenshot data

    Returns:
        Formatted CloudFlare abuse report
    """
    # Filter to only include CloudFlare-protected domains
    cloudflare_protected_domains = [
        inv.get("domain")
        for inv in all_investigations
        if inv.get("is_cloudflare_protected")
    ]

    return generate_abuse_report(
        investigation,
        "cloudflare",
        {
            "related_domains": [
                d
                for d in cloudflare_protected_domains
                if d != investigation.get("domain")
            ][:5],
            "urlscan_link": investigation.get("urlscan", {}).get("result_url"),
            "screenshots": False,
        },
        screenshot_analysis,
    )


def generate_all_reports(
    investigation: Dict,
    all_investigations: List[Dict],
    screenshot_analysis: Dict = None,
) -> Dict:
    """
    Generate a complete set of abuse reports for a domain

    Args:
        investigation: Domain investigation data
        all_investigations: All domain investigations for context
        screenshot_analysis: Optional screenshot analysis data
        enhanced_screenshot_data: Optional enhanced screenshot data

    Returns:
        Dictionary containing all abuse reports for the domain
    """
    # Get visual similarity group info if available
    visual_group_id = None
    visually_similar_domains = []
    screenshot_sim_dir = None

    if screenshot_analysis and investigation.get("domain"):
        visual_group_id, visually_similar_domains = get_screenshot_group_for_domain(
            investigation.get("domain"), screenshot_analysis
        )

        # Get screenshot similarity directory if available
        if visual_group_id is not None:
            base_dir = os.path.join(
                os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                ),
                "screenshot_groups",
            )

            # Check if enhanced directory exists
            enhanced_group_dir = os.path.join(
                base_dir, "enhanced", "groups", f"group_{visual_group_id}"
            )
            regular_group_dir = os.path.join(
                base_dir, "groups", f"group_{visual_group_id}"
            )

            if os.path.exists(enhanced_group_dir):
                screenshot_sim_dir = enhanced_group_dir
            elif os.path.exists(regular_group_dir):
                screenshot_sim_dir = regular_group_dir

    # Find composite image if available
    composite_image = None
    if screenshot_sim_dir:
        composite_path = os.path.join(
            screenshot_sim_dir, f"group_{visual_group_id}_composite.png"
        )
        if os.path.exists(composite_path):
            composite_image = composite_path

    return {
        "domain": investigation.get("domain"),
        "registrar_report": generate_registrar_report(
            investigation, all_investigations, screenshot_analysis
        ),
        "cloudflare_report": generate_cloudflare_report(
            investigation, all_investigations, screenshot_analysis
        ),
        "urlscan_link": investigation.get("urlscan", {}).get("result_url"),
        "visual_similarity": (
            {
                "group_id": visual_group_id,
                "similar_domains": visually_similar_domains,
                "total_in_group": (
                    len(visually_similar_domains) + 1 if visually_similar_domains else 0
                ),
                "screenshot_sim_dir": screenshot_sim_dir,
                "composite_image": composite_image,
            }
            if visual_group_id is not None
            else None
        ),
    }


def load_investigation_files(directory: str) -> List[Dict]:
    """
    Load all investigation JSON files from a directory

    Args:
        directory: Path to directory containing investigation files

    Returns:
        List of investigation data dictionaries
    """
    investigations = []

    for filename in os.listdir(directory):
        if filename.endswith("_investigation.json"):
            try:
                with open(os.path.join(directory, filename), "r") as f:
                    data = json.load(f)
                    investigations.append(data)
            except Exception as e:
                print(f"Error loading {filename}: {str(e)}")

    return investigations


def load_screenshot_analysis(file_path: str = None) -> Optional[Dict]:
    """
    Load screenshot analysis report

    Args:
        file_path: Path to the screenshot analysis JSON file.
                  If None, will try to load from default location.

    Returns:
        Screenshot analysis data dictionary or None if file not found/invalid
    """
    if file_path is None:
        # Use the default location in the screenshot_groups directory
        file_path = os.path.join(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            ),
            "screenshot_groups",
            "screenshot-analysis-report.json",
        )

    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                data = json.load(f)
                return data
        else:
            print(f"Screenshot analysis file not found: {file_path}")
            return None
    except Exception as e:
        print(f"Error loading screenshot analysis: {str(e)}")
        return None


def get_screenshot_group_for_domain(
    domain: str, screenshot_analysis: Dict
) -> Tuple[Optional[int], Optional[List[str]]]:
    """
    Find the visual similarity group that contains a specific domain

    Args:
        domain: The domain to look for (without '_' suffix)
        screenshot_analysis: The screenshot analysis data

    Returns:
        Tuple of (group_id, related_domains) or (None, None) if not found
    """
    if not screenshot_analysis or "groups" not in screenshot_analysis:
        return None, None

    # Some domains in the analysis have '_' suffix, handle both cases
    domain_with_suffix = f"{domain}_"
    domain_without_suffix = domain.rstrip("_")

    for group in screenshot_analysis.get("groups", []):
        domains_in_group = group.get("domains", [])

        # Check if this domain is in the group
        if any(d.startswith(domain_without_suffix) for d in domains_in_group):
            # Return the group ID and all domains except the input domain
            related_domains = [
                d.rstrip("_")  # Remove trailing underscore if present
                for d in domains_in_group
                if not d.startswith(domain_without_suffix)
            ]
            return group.get("group_id"), related_domains

    return None, None


def save_report(report: Dict, output_dir: str, domain: str, report_type: str) -> None:
    """
    Save a report to a JSON file

    Args:
        report: Report data to save
        output_dir: Directory to save the report in
        domain: Domain name for the filename
        report_type: Type of report for the filename
    """
    os.makedirs(output_dir, exist_ok=True)

    filename = f"{domain}_{report_type}_report.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Saved report to {filepath}")


# Example usage
if __name__ == "__main__":
    import os.path
    import sys

    if len(sys.argv) < 3:
        print(
            "Usage: python abuse_report_generator.py <investigation_dir> <output_dir> [screenshot_analysis_file]"
        )
        sys.exit(1)

    investigation_dir = sys.argv[1]
    output_dir = sys.argv[2]

    # Optional screenshot analysis file path
    screenshot_analysis_file = None
    if len(sys.argv) > 3:
        screenshot_analysis_file = sys.argv[3]

    # Load all investigations
    print(f"Loading investigations from {investigation_dir}...")
    all_investigations = load_investigation_files(investigation_dir)
    print(f"Loaded {len(all_investigations)} domain investigations")

    # Load screenshot analysis data if available
    screenshot_analysis = load_screenshot_analysis(screenshot_analysis_file)
    if screenshot_analysis:
        print(
            f"Loaded screenshot analysis data with {screenshot_analysis.get('total_groups', 0)} visual similarity groups"
        )
        print(
            f"Total screenshots analyzed: {screenshot_analysis.get('total_screenshots', 0)}"
        )
    else:
        print("No screenshot analysis data available or could not be loaded")

    # Generate campaign summary
    campaign_summary = generate_campaign_summary(all_investigations)
    save_report(campaign_summary, output_dir, "campaign", "summary")

    # Generate individual domain reports
    for investigation in all_investigations:
        domain = investigation.get("domain")
        print(f"Generating reports for {domain}...")

        reports = generate_all_reports(
            investigation, all_investigations, screenshot_analysis
        )
        save_report(reports, output_dir, domain, "all")

        # Check for visual similarity information and log it if present
        if (
            reports.get("visual_similarity")
            and reports["visual_similarity"].get("group_id") is not None
        ):
            screenshot_dir_info = ""
            if reports["visual_similarity"].get("screenshot_sim_dir"):
                screenshot_dir_info = f" (evidence in {reports['visual_similarity']['screenshot_sim_dir']})"

            print(
                f"  Domain {domain} is part of visual similarity Group {reports['visual_similarity']['group_id']} "
                f"with {reports['visual_similarity']['total_in_group']} domains{screenshot_dir_info}"
            )

    # Generate a summary of visual similarity groups for reference
    if screenshot_analysis:
        visual_summary = {
            "timestamp": screenshot_analysis.get("timestamp"),
            "total_groups": screenshot_analysis.get("total_groups"),
            "total_screenshots": screenshot_analysis.get("total_screenshots"),
            "group_sizes": {
                f"group_{group['group_id']}": {
                    "count": group["count"],
                    "domains": group["domains"],
                    "screenshot_dir": os.path.join(
                        "screenshot_groups", "groups", f"group_{group['group_id']}"
                    ),
                }
                for group in screenshot_analysis.get("groups", [])
            },
        }
        save_report(visual_summary, output_dir, "visual_similarity", "summary")
        print(f"Generated visual similarity group summary with screenshot directories")

    print("Done!")
