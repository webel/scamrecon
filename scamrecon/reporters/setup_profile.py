#!/usr/bin/env python
"""
Improved script for setting up a browser profile for Cloudflare abuse reporting.
Creates a persistent profile with cookies that can be reused by the main reporter.
"""

import argparse
import os
import pickle
import time
from typing import Dict

import undetected_chromedriver as uc
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def setup_browser_profile():
    """Set up a browser profile for Cloudflare abuse reporting"""
    parser = argparse.ArgumentParser(
        description="Setup browser profile for Cloudflare reporting"
    )
    parser.add_argument(
        "--profile-dir",
        default="chrome_profile",
        help="Directory to store browser profile",
    )
    parser.add_argument(
        "--cookie-file",
        default="reports/cloudflare_cookies.pkl",
        help="Path to save cookies",
    )
    args = parser.parse_args()

    # Create directories
    profile_dir = os.path.abspath(args.profile_dir)
    cookie_dir = os.path.dirname(args.cookie_file)
    os.makedirs(profile_dir, exist_ok=True)
    os.makedirs(cookie_dir, exist_ok=True)

    print(f"Setting up browser profile in: {profile_dir}")
    print(f"Cookies will be saved to: {args.cookie_file}")

    # Setup Chrome options - minimal but effective
    options = uc.ChromeOptions()
    options.add_argument(f"--user-data-dir={profile_dir}")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_argument("--window-size=1366,768")

    # Language settings that look normal
    options.add_argument("--lang=en-US,en;q=0.9")

    print("\nStarting browser for profile setup...")

    # Initialize the driver with undetected_chromedriver
    driver = uc.Chrome(options=options, use_subprocess=True)
    wait = WebDriverWait(driver, 10)

    try:
        # Basic webdriver removal
        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        # Load the Cloudflare abuse form
        print("Loading Cloudflare abuse reporting page...")
        driver.get("https://abuse.cloudflare.com/phishing")

        # Wait for form to load
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "form")))
        print("Form loaded successfully")

        print("\n" + "=" * 60)
        print("PROFILE SETUP INSTRUCTIONS:")
        print("1. Complete at least one report submission")
        print("2. Solve any CAPTCHAs that appear")
        print("3. Accept any cookies or consent dialogs")
        print("4. After successful submission, the browser state will be saved")
        print("=" * 60 + "\n")

        input("Press Enter when you're ready to start interacting with the form...")

        # Wait for user to complete a report submission
        print("Please complete the form and submit a report. The script will wait.")
        input("Press Enter when you've successfully submitted a report...")

        # Save cookies and local storage
        cookies = driver.get_cookies()

        # Get local storage
        local_storage = {}
        local_storage_keys = driver.execute_script("return Object.keys(localStorage)")
        for key in local_storage_keys:
            value = driver.execute_script(f"return localStorage.getItem('{key}')")
            local_storage[key] = value

        # Save state data
        state_data = {
            "cookies": cookies,
            "local_storage": local_storage,
            "last_saved": time.time(),
        }

        with open(args.cookie_file, "wb") as f:
            pickle.dump(state_data, f)

        print(f"\n✅ Browser state saved to {args.cookie_file}")

    finally:
        # Clean up
        driver.quit()

    print(
        "\nProfile setup complete! You can now use this profile with CloudflareReporter"
    )
    print("When using the reporter, specify the cookie file with:")
    print(f"  --cookie-file={args.cookie_file}")

    return 0


if __name__ == "__main__":
    setup_browser_profile()
