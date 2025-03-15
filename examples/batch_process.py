#!/usr/bin/env python3
"""
Example script showing how to use ScamRecon to batch process domains.
"""
import os
import sys

from scamrecon.analyzers.screenshot import batch_capture_screenshots
from scamrecon.analyzers.tech_detector import process_domains
from scamrecon.core.domain_investigator import batch_investigate_domains
from scamrecon.reporters.cloudflare import batch_submit_reports


def main():
    """Main function to batch process domains."""
    if len(sys.argv) < 3:
        print("Usage: python batch_process.py <mode> <csv_file> [--skip N]")
        print("Modes: tech, screenshot, investigate, report")
        print("Options:")
        print("  --skip N    Skip first N lines of the CSV file")
        sys.exit(1)

    mode = sys.argv[1].lower()
    csv_file = sys.argv[2]
    
    # Parse skip parameter if provided
    skip_lines = 0
    if len(sys.argv) > 3 and sys.argv[3] == "--skip" and len(sys.argv) > 4:
        try:
            skip_lines = int(sys.argv[4])
        except ValueError:
            print(f"Error: Invalid value for --skip: {sys.argv[4]}")
            sys.exit(1)

    if not os.path.exists(csv_file):
        print(f"Error: File not found: {csv_file}")
        sys.exit(1)

    if mode == "tech":
        # Create output directory
        os.makedirs("tech_results", exist_ok=True)

        print(f"Processing technology detection for domains in {csv_file} (skipping {skip_lines} lines)...")
        process_domains(csv_file, output_dir="tech_results", timeout=20, skip_lines=skip_lines)

    elif mode == "screenshot":
        # Create output directory
        os.makedirs("screenshots", exist_ok=True)

        print(f"Capturing screenshots for domains in {csv_file} (skipping {skip_lines} lines)...")
        batch_capture_screenshots(csv_file, output_dir="screenshots", skip_lines=skip_lines)

    elif mode == "investigate":
        # Create output directory
        os.makedirs("investigation_results", exist_ok=True)
        
        print(f"Running domain investigations for domains in {csv_file} (skipping {skip_lines} lines)...")
        batch_investigate_domains(csv_file, output_dir="investigation_results", timeout=20, skip_lines=skip_lines)
        
    elif mode == "report":
        # Create output directory
        os.makedirs("reports", exist_ok=True)
        output_file = "reports/report_results.json"
        
        print(f"Reporting domains from {csv_file} to Cloudflare (skipping {skip_lines} lines)...")
        
        # Get report information from user
        print("Please provide the following information for your reports:")
        
        report_data = {
            "name": input("Your name: "),
            "email": input("Your email: "),
            "title": input("Your title (optional, press Enter to skip): "),
            "company": input("Company name (optional, press Enter to skip): "),
            "telephone": input("Phone number (optional, press Enter to skip): "),
            "justification": input(
                "Justification/evidence (detailed description of the phishing activity): "
            ),
            "targeted_brand": input("Targeted brand URL or description: "),
            "comments": input("Additional comments (optional, press Enter to skip): "),
            "include_contact_info": input(
                "Include your contact info with forwarded reports? (y/n): "
            ).lower()
            == "y",
        }

        # Remove empty fields
        report_data = {k: v for k, v in report_data.items() if v}
        
        batch_submit_reports(
            domains_file=csv_file,
            output_file=output_file,
            report_data=report_data,
            batch_size=50,
            headless=False,
            timeout=20,
            skip_lines=skip_lines,
        )
        
    else:
        print(f"Error: Unknown mode: {mode}")
        print("Available modes: tech, screenshot, investigate, report")
        sys.exit(1)


if __name__ == "__main__":
    main()

