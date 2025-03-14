#!/usr/bin/env python3
"""
Example script showing how to use ScamRecon to investigate a domain.
"""
import json
import os
import sys

from scamrecon.core.domain_investigator import DomainInvestigator
from scamrecon.utils.config import Config


def main():
    """Main function to run domain investigation."""
    # Check if domain was provided
    if len(sys.argv) < 2:
        print("Usage: python investigate_domain.py <domain_name>")
        sys.exit(1)

    # Get domain from command line
    domain = sys.argv[1]

    # Create output directory
    os.makedirs("results", exist_ok=True)

    # Configure investigation
    config = Config.load_default()
    config.timeout = 10
    config.verbose = True
    config.scan_malware = True

    # Output file
    output_file = f"results/{domain}_investigation.json"

    # Create investigator and run
    investigator = DomainInvestigator(domain, config, output_file=output_file)
    results = investigator.run_investigation()

    # Print summary
    print(f"\nInvestigation completed for {domain}")
    print(f"Results saved to {output_file}")

    if results["confirmed_origins"]:
        print(f"\nFound {len(results['confirmed_origins'])} origin IPs:")
        for origin in results["confirmed_origins"]:
            print(f"  - {origin['ip']}")
    else:
        print("\nNo origin IPs found.")

    # Print security issues
    if results["security_issues"]:
        print(f"\nFound {len(results['security_issues'])} security issues:")
        for issue in results["security_issues"]:
            print(f"  - {issue['issue']} ({issue['severity']})")
    else:
        print("\nNo security issues found.")


if __name__ == "__main__":
    main()

