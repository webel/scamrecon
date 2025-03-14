#!/usr/bin/env python3
"""
Example script showing how to use ScamRecon to capture a screenshot of a website.
"""
import os
import sys

from scamrecon.analyzers.screenshot import ScreenshotCapture


def main():
    """Main function to capture a screenshot."""
    # Check if domain was provided
    if len(sys.argv) < 2:
        print("Usage: python capture_screenshot.py <domain_name>")
        sys.exit(1)

    # Get domain from command line
    domain = sys.argv[1]

    # Create output directory
    os.makedirs("screenshots", exist_ok=True)

    # Create screenshot capturer and run
    capturer = ScreenshotCapture(output_dir="screenshots", timeout=20, headless=True)

    try:
        print(f"Capturing screenshot for {domain}...")
        result = capturer.capture_screenshot(domain)

        if result["success"]:
            print(
                f"Screenshot captured successfully and saved to {result['screenshot_path']}"
            )
            if result["redirected_url"]:
                print(f"Redirected to: {result['redirected_url']}")
        else:
            print(f"Failed to capture screenshot: {result['error']}")

    finally:
        capturer.close()


if __name__ == "__main__":
    main()

