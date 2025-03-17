"""
Scam Campaign Analysis Tool

This script integrates domain investigation data with screenshot similarity analysis
to generate comprehensive abuse reports for phishing/scam campaigns.
"""

import argparse
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from scamrecon.reporters.create_evidence import (
    generate_all_reports,
    generate_campaign_summary,
    identify_campaigns,
    load_investigation_files,
)
from scamrecon.reporters.screenshot_similarity import (
    ScreenshotAnalyzer,
    analyze_novelty_patterns,
    enhance_reports_with_screenshot_analysis,
)


def analyze_scam_campaign(options: Dict) -> Dict:
    """
    Main function to analyze a scam campaign and generate reports.

    Args:
        options: Configuration options including paths to data

    Returns:
        Analysis results
    """
    investigation_dir = options.get("investigation_dir")
    screenshot_dir = options.get("screenshot_dir")
    output_dir = options.get("output_dir")
    reporter = options.get("reporter", {})

    print("Starting scam campaign analysis...")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: Load all investigation data
    print("Loading investigation data...")
    investigations = load_investigation_files(investigation_dir)
    print(f"Loaded {len(investigations)} domain investigations.")

    # Step 2: Analyze screenshots for visual similarity
    print("Analyzing screenshot similarity...")
    screenshot_analysis_dir = os.path.join(output_dir, "screenshot-analysis")
    analyzer = ScreenshotAnalyzer()
    screenshot_results = analyzer.run(screenshot_dir, screenshot_analysis_dir)

    # Step 3: Identify campaigns based on infrastructure
    print("Identifying campaigns based on infrastructure...")
    campaigns = identify_campaigns(investigations)

    # Step 4: Integrate screenshot analysis with infrastructure analysis
    print("Integrating analysis results...")
    enhanced_data = enhance_reports_with_screenshot_analysis(
        screenshot_dir, os.path.join(output_dir, "enhanced-data"), investigations
    )

    # Step 5: Generate campaign report
    print("Generating campaign summary...")
    campaign_summary = generate_campaign_summary(investigations)

    # Add screenshot analysis to campaign summary
    campaign_summary["visual_patterns"] = {
        "total_groups": screenshot_results.get("total_groups", 0),
        "visual_similarity_groups": [
            {
                "group_id": group.get("group_id"),
                "domains": group.get("domains"),
                "count": group.get("count"),
            }
            for group in screenshot_results.get("groups", [])
        ],
    }

    # Save campaign summary
    with open(os.path.join(output_dir, "campaign-summary.json"), "w") as f:
        json.dump(campaign_summary, f, indent=2)

    # Step 6: Generate abuse reports for each domain
    print("Generating abuse reports...")
    report_output_dir = os.path.join(output_dir, "reports")
    os.makedirs(report_output_dir, exist_ok=True)

    reports_generated = {}

    for investigation in investigations:
        try:
            domain = investigation.get("domain")
            if not domain:
                continue

            # Find visual group for this domain
            visual_group = None
            for domain_info in enhanced_data.get("enhanced_domain_data", []):
                if domain_info.get("domain") == domain:
                    visual_group = domain_info.get("screenshot_analysis")
                    break

            # Generate all types of reports for this domain
            domain_reports = generate_all_reports(investigation, investigations)

            # Add visual similarity evidence to reports
            if visual_group and visual_group.get("group_id"):
                visual_evidence = {
                    "visual_group_id": visual_group.get("group_id"),
                    "similar_appearance_domains": visual_group.get(
                        "similar_domains", []
                    ),
                    "screenshot_evidence_path": f"groups/group_{visual_group.get('group_id')}/group_{visual_group.get('group_id')}_composite.png",
                }

                # Enhance each report type with visual evidence
                for report_type in ["registrar_report", "cloudflare_report"]:
                    if report_type in domain_reports:
                        domain_reports[report_type]["visual_evidence"] = visual_evidence

                        # Add to justification
                        visual_evidence_text = f" Visual analysis confirms this domain uses identical phishing pages to {len(visual_group.get('similar_domains', []))} other domains in this campaign."
                        domain_reports[report_type][
                            "justification"
                        ] += visual_evidence_text

            # Save the reports
            with open(
                os.path.join(report_output_dir, f"{domain}_reports.json"), "w"
            ) as f:
                json.dump(domain_reports, f, indent=2)

            reports_generated[domain] = True

        except Exception as e:
            print(
                f"Error generating reports for {investigation.get('domain')}: {str(e)}"
            )

    # Step 7: Generate novelty analysis
    print("Analyzing novelty patterns...")
    novelty_analysis = analyze_novelty_patterns(investigations, enhanced_data)

    with open(os.path.join(output_dir, "novelty-analysis.json"), "w") as f:
        json.dump(novelty_analysis, f, indent=2)

    print("Analysis complete!")
    return {
        "domains_analyzed": len(investigations),
        "infrastructure_campaigns": len(campaigns),
        "visual_groups": screenshot_results.get("total_groups", 0),
        "reports_generated": len(reports_generated),
        "campaign_summary": campaign_summary,
        "novelty_analysis": novelty_analysis,
    }


def generate_form_templates(output_dir: str) -> None:
    """
    Generate standardized form templates for various abuse report destinations.

    Args:
        output_dir: Directory to save templates
    """
    print("Generating abuse report form templates...")

    templates = {
        "registrar": {
            "title": "Domain Abuse Report Template",
            "fields": [
                {"name": "reporter_name", "type": "text", "required": True},
                {"name": "reporter_email", "type": "email", "required": True},
                {"name": "reporter_company", "type": "text", "required": True},
                {"name": "domain", "type": "text", "required": True},
                {
                    "name": "abuse_type",
                    "type": "select",
                    "options": ["phishing", "malware", "scam"],
                    "required": True,
                },
                {"name": "evidence", "type": "textarea", "required": True},
                {"name": "additional_info", "type": "textarea", "required": False},
            ],
            "instructions": "Include domain WHOIS information and evidence of fraudulent activity.",
        },
        "cloudflare": {
            "title": "CloudFlare Abuse Report Template",
            "fields": [
                {"name": "reporter_name", "type": "text", "required": True},
                {"name": "reporter_email", "type": "email", "required": True},
                {"name": "reporter_company", "type": "text", "required": True},
                {"name": "domain", "type": "text", "required": True},
                {"name": "cloudflare_ray_id", "type": "text", "required": False},
                {
                    "name": "abuse_type",
                    "type": "select",
                    "options": ["phishing", "malware", "scam"],
                    "required": True,
                },
                {"name": "evidence", "type": "textarea", "required": True},
                {"name": "additional_domains", "type": "textarea", "required": False},
            ],
            "instructions": "Include CloudFlare Ray IDs if available and evidence of fraudulent activity.",
        },
        "hosting": {
            "title": "Hosting Provider Abuse Report Template",
            "fields": [
                {"name": "reporter_name", "type": "text", "required": True},
                {"name": "reporter_email", "type": "email", "required": True},
                {"name": "reporter_company", "type": "text", "required": True},
                {"name": "domain", "type": "text", "required": True},
                {"name": "ip_addresses", "type": "text", "required": True},
                {
                    "name": "abuse_type",
                    "type": "select",
                    "options": ["phishing", "malware", "scam"],
                    "required": True,
                },
                {"name": "evidence", "type": "textarea", "required": True},
                {"name": "urlscan_link", "type": "text", "required": False},
            ],
            "instructions": "Include server IP addresses and evidence of fraudulent activity.",
        },
    }

    os.makedirs(output_dir, exist_ok=True)

    for template_name, template_data in templates.items():
        with open(os.path.join(output_dir, f"{template_name}_template.json"), "w") as f:
            json.dump(template_data, f, indent=2)

    print(f"Templates generated in {output_dir}")


def main():
    """Command line interface for the scam campaign analysis tool."""
    parser = argparse.ArgumentParser(description="Scam Campaign Analysis Tool")

    parser.add_argument(
        "--investigations",
        required=True,
        help="Directory containing JSON investigation files",
    )
    parser.add_argument(
        "--screenshots", required=True, help="Directory containing screenshot files"
    )
    parser.add_argument("--output", required=True, help="Directory for output reports")
    parser.add_argument(
        "--templates", action="store_true", help="Generate abuse report form templates"
    )

    args = parser.parse_args()

    # Check if directories exist
    for dir_path, dir_name in [
        (args.investigations, "Investigations"),
        (args.screenshots, "Screenshots"),
    ]:
        if not os.path.exists(dir_path):
            print(f"{dir_name} directory does not exist: {dir_path}")
            return 1

    # Create output directory if it doesn't exist
    os.makedirs(args.output, exist_ok=True)

    # Generate templates if requested
    if args.templates:
        templates_dir = os.path.join(args.output, "templates")
        generate_form_templates(templates_dir)

    # Run the analysis
    options = {
        "investigation_dir": args.investigations,
        "screenshot_dir": args.screenshots,
        "output_dir": args.output,
        "reporter": {
            "name": "Cookie",
            "email": "slaymeacookie@gmail.com",
            "title": "Security Analyst",
            "company": "HackBack",
        },
    }

    results = analyze_scam_campaign(options)

    # Print summary
    print("\nAnalysis Summary:")
    print(f"- Domains analyzed: {results['domains_analyzed']}")
    print(
        f"- Infrastructure campaigns identified: {results['infrastructure_campaigns']}"
    )
    print(f"- Visual similarity groups: {results['visual_groups']}")
    print(f"- Abuse reports generated: {results['reports_generated']}")
    print(f"\nResults saved to: {args.output}")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
