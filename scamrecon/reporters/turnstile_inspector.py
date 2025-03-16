#!/usr/bin/env python
"""
Turnstile Inspector - A diagnostic tool for Cloudflare Turnstile issues.
Fixed version for compatibility with all undetected_chromedriver versions.
"""

import argparse
import json
import os
import random
import time
from typing import Any, Dict, List, Optional

import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class TurnstileInspector:
    """Diagnostic tool for analyzing Turnstile challenges"""

    def __init__(self, headless: bool = False):
        """Initialize the inspector"""
        self.headless = headless
        self.driver = None
        self.messages = []
        self.setup_driver()

    def setup_driver(self):
        """Setup browser with monitoring capabilities"""
        options = uc.ChromeOptions()

        if self.headless:
            options.add_argument("--headless")

        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1280,800")
        options.add_argument("--disable-blink-features=AutomationControlled")

        # Create driver
        self.driver = uc.Chrome(options=options, use_subprocess=True)

        # Inject message monitoring script
        monitor_script = """
        // Store all Turnstile messages
        window.turnstileMessages = [];
        
        // Setup message listener
        window.addEventListener('message', function(event) {
            try {
                if (event.data && 
                    (event.data.source === 'cloudflare-challenge' || 
                     typeof event.data === 'object' && 'widgetId' in event.data)) {
                    window.turnstileMessages.push({
                        timestamp: new Date().getTime(),
                        data: JSON.parse(JSON.stringify(event.data)),
                        origin: event.origin
                    });
                }
            } catch (e) {
                console.error('Error processing message:', e);
            }
        }, false);
        """

        self.driver.get("about:blank")
        self.driver.execute_script(monitor_script)

    def navigate_to_form(self, url: str = "https://abuse.cloudflare.com/phishing"):
        """Navigate to the form"""
        self.driver.get(url)

        # Wait for form to load
        try:
            WebDriverWait(self.driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "form"))
            )
            print("Form loaded successfully")
            return True
        except Exception as e:
            print(f"Error loading form: {e}")
            return False

    def collect_messages(self) -> List[Dict[str, Any]]:
        """Collect all Turnstile messages"""
        try:
            messages = self.driver.execute_script("return window.turnstileMessages;")
            self.messages.extend(messages or [])
            return messages or []
        except Exception as e:
            print(f"Error collecting messages: {e}")
            return []

    def clear_messages(self):
        """Clear collected messages"""
        self.driver.execute_script("window.turnstileMessages = [];")
        self.messages = []

    def inspect_turnstile(self, duration: int = 60, form_fill: bool = False):
        """
        Run a complete inspection of the Turnstile challenge

        Args:
            duration: How long to monitor in seconds
            form_fill: Whether to automatically fill out the form
        """
        if not self.navigate_to_form():
            print("Failed to load form, aborting inspection")
            return

        # Fill form if requested
        if form_fill:
            try:
                self._fill_basic_form()
            except Exception as e:
                print(f"Error filling form: {e}")

        print(f"Monitoring Turnstile messages for {duration} seconds...")
        print("Solve the CAPTCHA if it appears")

        # Monitor for specified duration
        start_time = time.time()
        while time.time() - start_time < duration:
            new_messages = self.collect_messages()
            if new_messages:
                print(f"Collected {len(new_messages)} new messages")
            time.sleep(1)

        # Analyze results
        self._analyze_results()

    def _fill_basic_form(self):
        """Fill in the form with basic data"""
        # Name
        name_field = self.driver.find_element(By.NAME, "name")
        name_field.clear()
        name_field.send_keys("John Doe")
        time.sleep(random.uniform(0.5, 1.0))

        # Email
        email_field = self.driver.find_element(By.NAME, "email")
        email_field.clear()
        email_field.send_keys("test@example.com")
        time.sleep(random.uniform(0.5, 1.0))

        # Confirm email
        email2_field = self.driver.find_element(By.NAME, "email2")
        email2_field.clear()
        email2_field.send_keys("test@example.com")
        time.sleep(random.uniform(0.5, 1.0))

        # Evidence URLs
        urls_field = self.driver.find_element(By.NAME, "urls")
        urls_field.clear()
        urls_field.send_keys("https://malicious-example.com")
        time.sleep(random.uniform(0.5, 1.0))

        # Justification
        justification_field = self.driver.find_element(By.NAME, "justification")
        justification_field.clear()
        justification_field.send_keys(
            "This is a test submission for diagnostic purposes"
        )
        time.sleep(random.uniform(0.5, 1.0))

        # Scroll down to checkboxes
        self.driver.execute_script("window.scrollBy(0, 300);")
        time.sleep(1)

        # DSA certification checkbox (last one)
        checkboxes = self.driver.find_elements(
            By.CSS_SELECTOR, "input[type='checkbox']:not([readonly])"
        )
        if checkboxes:
            dsa_checkbox = checkboxes[-1]
            if not dsa_checkbox.is_selected():
                self.driver.execute_script("arguments[0].click();", dsa_checkbox)

        print("Form filled with test data")

    def _analyze_results(self):
        """Analyze the collected messages"""
        if not self.messages:
            print("No Turnstile messages were captured")
            return

        # Count message types
        message_types = {}
        events = {}
        error_codes = {}

        for msg in self.messages:
            event = msg.get("data", {}).get("event")
            if event:
                events[event] = events.get(event, 0) + 1

            error_code = msg.get("data", {}).get("code")
            if error_code:
                error_codes[error_code] = error_codes.get(error_code, 0) + 1

        # Print summary
        print("\n==== Turnstile Inspection Results ====")
        print(f"Total messages captured: {len(self.messages)}")

        print("\nEvents:")
        for event, count in events.items():
            print(f"  - {event}: {count}")

        if error_codes:
            print("\nError Codes:")
            for code, count in error_codes.items():
                print(f"  - {code}: {count}")

                # Provide insights for common errors
                if code == 300030:
                    print("    > Widget hung - Likely due to automation detection")
                elif code == 300031:
                    print(
                        "    > Widget crashed - Likely due to iframe manipulation issues"
                    )

        # Check for watchcat messages
        watchcat_messages = [
            m for m in self.messages if m.get("data", {}).get("event") == "meow"
        ]
        if watchcat_messages:
            print(f"\nWatchcat 'meow' messages: {len(watchcat_messages)}")

        # Check for food responses
        food_messages = [
            m for m in self.messages if m.get("data", {}).get("event") == "food"
        ]
        if food_messages:
            print(f"Watchcat 'food' responses: {len(food_messages)}")
            ack_ratio = len(food_messages) / max(len(watchcat_messages), 1)
            print(f"Acknowledgment ratio: {ack_ratio:.2f}")

            if ack_ratio < 0.5:
                print(
                    "WARNING: Low acknowledgment ratio suggests iframe communication issues"
                )

        # Save raw data to file
        try:
            with open("turnstile_messages.json", "w") as f:
                json.dump(self.messages, f, indent=2)
                print("\nRaw message data saved to 'turnstile_messages.json'")
        except Exception as e:
            print(f"Error saving message data: {e}")

    def close(self):
        """Close the browser"""
        if self.driver:
            self.driver.quit()


def main():
    parser = argparse.ArgumentParser(description="Diagnose Cloudflare Turnstile issues")
    parser.add_argument(
        "--duration", type=int, default=60, help="Duration to monitor in seconds"
    )
    parser.add_argument("--headless", action="store_true", help="Run in headless mode")
    parser.add_argument(
        "--fill-form", action="store_true", help="Auto-fill the form with test data"
    )

    args = parser.parse_args()

    inspector = TurnstileInspector(headless=args.headless)

    try:
        inspector.inspect_turnstile(duration=args.duration, form_fill=args.fill_form)
    finally:
        inspector.close()


if __name__ == "__main__":
    main()
