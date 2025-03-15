#!/usr/bin/env python3
"""
Example script for submitting reports to Cloudflare using a JSON file for report fields.
"""

import argparse
import os
import sys

# Add the parent directory to the path so we can import scamrecon
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scamrecon.reporters.cloudflare import batch_submit_reports


def main():
    parser = argparse.ArgumentParser(
        description="Report phishing domains to Cloudflare"
    )
    parser.add_argument(
        "domains_file", help="File containing list of domains to report"
    )
    parser.add_argument(
        "--report-fields", help="JSON file with report fields", required=True
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file for results",
        default="cf_report_results.json",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=300,
        help="Number of domains to process (each domain is submitted as a separate report)",
    )
    parser.add_argument("--headless", action="store_true", help="Run in headless mode")
    parser.add_argument(
        "--timeout", type=int, default=20, help="Timeout for page loads in seconds"
    )
    args = parser.parse_args()

    # Load report fields from JSON file
    try:
        import json

        with open(args.report_fields, "r") as f:
            report_data = json.load(f)
        print(f"Loaded report data from {args.report_fields}")
    except Exception as e:
        print(f"Error loading report fields: {e}")
        return 1

    # Submit reports
    batch_submit_reports(
        domains_file=args.domains_file,
        output_file=args.output,
        report_data=report_data,
        batch_size=args.batch_size,
        headless=args.headless,
        timeout=args.timeout,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())

