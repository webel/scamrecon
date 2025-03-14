#!/usr/bin/env python3
"""
Example script showing how to use ScamRecon to detect technologies used by a website.
"""
import json
import os
import sys

from scamrecon.analyzers.tech_detector import TechDetector


def main():
    """Main function to run technology detection."""
    # Check if domain was provided
    if len(sys.argv) < 2:
        print("Usage: python tech_detection.py <domain_name>")
        sys.exit(1)

    # Get domain from command line
    domain = sys.argv[1]

    # Create output directory
    os.makedirs("results", exist_ok=True)

    # Output file
    output_file = f"results/{domain}_tech.json"

    # Create detector and run
    detector = TechDetector(headless=True, timeout=20)

    try:
        result = detector.detect_technologies(domain)

        # Save result
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)

        # Print summary
        print(f"\nTechnology detection completed for {domain}")
        print(f"Results saved to {output_file}")

        # Print detected technologies
        technologies = result.get("technologies", {})
        if technologies:
            print("\nDetected technologies:")
            for category, techs in technologies.items():
                print(f"  {category.upper()}:")
                for tech in techs:
                    print(f"    - {tech}")
        else:
            print("\nNo technologies detected.")

        # Print server info
        server_info = result.get("server_info", {})
        if server_info:
            print("\nServer information:")
            for key, value in server_info.items():
                print(f"  {key}: {value}")

    finally:
        detector.close()


if __name__ == "__main__":
    main()

