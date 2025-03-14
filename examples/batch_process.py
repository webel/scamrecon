#!/usr/bin/env python3
"""
Example script showing how to use ScamRecon to batch process domains.
"""
import os
import sys

from scamrecon.analyzers.screenshot import batch_capture_screenshots
from scamrecon.analyzers.tech_detector import process_domains


def main():
    """Main function to batch process domains."""
    if len(sys.argv) < 3:
        print("Usage: python batch_process.py <mode> <csv_file>")
        print("Modes: tech, screenshot")
        sys.exit(1)

    mode = sys.argv[1].lower()
    csv_file = sys.argv[2]

    if not os.path.exists(csv_file):
        print(f"Error: File not found: {csv_file}")
        sys.exit(1)

    if mode == "tech":
        # Create output directory
        os.makedirs("tech_results", exist_ok=True)

        print(f"Processing technology detection for domains in {csv_file}...")
        process_domains(csv_file, output_dir="tech_results", timeout=20)

    elif mode == "screenshot":
        # Create output directory
        os.makedirs("screenshots", exist_ok=True)

        print(f"Capturing screenshots for domains in {csv_file}...")
        batch_capture_screenshots(csv_file, output_dir="screenshots")

    else:
        print(f"Error: Unknown mode: {mode}")
        print("Available modes: tech, screenshot")
        sys.exit(1)


if __name__ == "__main__":
    main()

