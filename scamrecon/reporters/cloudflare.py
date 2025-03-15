"""
Cloudflare Abuse Report Automation Tool
For reporting large numbers of phishing domains.
"""

import csv
import json
import os
import pickle
import random
import time
from pathlib import Path
from typing import Dict, List, Optional

import undetected_chromedriver as uc
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait


class CloudflareReporter:
    """
    Submits phishing reports to Cloudflare's abuse portal.
    Each domain is submitted as a separate report.
    """

    def __init__(
        self,
        output_dir: str = "reports",
        timeout: int = 20,
        headless: bool = False,  # Setting to False to help with debugging
        batch_size: int = 50,  # Number of domains to process (each as an individual report)
        cookie_file: str = None,  # Path to save/load cookies
    ):
        """
        Initialize the reporter.

        Args:
            output_dir: Directory to save report logs
            timeout: Page load timeout in seconds
            headless: Whether to run browser in headless mode
            batch_size: Number of domains to process in a batch (each as an individual report)
            cookie_file: Path to save/load cookies (to maintain session between runs)
        """
        self.output_dir = output_dir
        self.timeout = timeout
        self.headless = headless
        self.batch_size = batch_size
        self.cloudflare_url = "https://abuse.cloudflare.com/phishing"
        self.cookie_file = cookie_file or os.path.join(
            output_dir, "cloudflare_cookies.pkl"
        )

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Report counter for logging
        self.report_counter = 0

        # Session tokens (saved after successful form submission)
        self.session_tokens = {}

        # Flag to track if captcha was bypassed in previous submissions
        self.previously_bypassed_captcha = False

        # Setup driver
        self.setup_driver()

    def setup_driver(self):
        """Set up Chrome webdriver with undetected_chromedriver"""
        options = uc.ChromeOptions()

        if self.headless:
            options.add_argument("--headless")

        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")

        # Advanced bot detection bypass options
        options.add_argument("--disable-blink-features=AutomationControlled")

        # Random user agent to appear more like a regular browser
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0",
        ]
        import random

        options.add_argument(f"user-agent={random.choice(user_agents)}")

        self.driver = uc.Chrome(options=options)
        self.driver.set_page_load_timeout(self.timeout)

        # Execute stealth JS to make detection harder
        self.driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )

        # Add additional cookies and browser fingerprinting that appears more human-like
        self.driver.execute_cdp_cmd(
            "Network.setUserAgentOverride",
            {
                "userAgent": self.driver.execute_script("return navigator.userAgent"),
                "platform": "Windows",
            },
        )

        # Wait setup
        self.wait = WebDriverWait(self.driver, 10)

        # Try to load saved cookies
        self.load_cookies()

    def report_domain(self, domain: str, report_data: Dict) -> Dict:
        """
        Submit a report for a single domain.

        Args:
            domain: The domain to report
            report_data: Dictionary containing the report information

        Returns:
            Dictionary with report results
        """
        result = {
            "domain": domain,
            "success": False,
            "error": None,
            "report_number": self.report_counter + 1,
        }

        try:
            print(f"Loading Cloudflare abuse form for domain: {domain}")
            self.driver.get(self.cloudflare_url)

            # Wait for the form to load - looking for any form element
            self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "form")))
            print("Form detected on page")

            # No need to select "Phishing & Malware" option - it seems to be already selected based on the URL

            # Fill out form fields with explicit waits and error handling
            # Your name
            try:
                name_field = self.wait.until(
                    EC.element_to_be_clickable((By.NAME, "name"))
                )
                name_field.clear()  # Clear any existing text
                name_field.send_keys(report_data["name"])
                print("✓ Name field filled")
            except Exception as e:
                print(f"Error filling name field: {e}")
                result["error"] = f"Failed at name field: {str(e)}"
                return result

            # Email address
            try:
                email_field = self.wait.until(
                    EC.element_to_be_clickable((By.NAME, "email"))
                )
                email_field.clear()
                email_field.send_keys(report_data["email"])
                print("✓ Email field filled")
            except Exception as e:
                print(f"Error filling email field: {e}")
                result["error"] = f"Failed at email field: {str(e)}"
                return result

            # Confirm email address
            try:
                email2_field = self.wait.until(
                    EC.element_to_be_clickable((By.NAME, "email2"))
                )
                email2_field.clear()
                email2_field.send_keys(report_data["email"])
                print("✓ Confirm email field filled")
            except Exception as e:
                print(f"Error filling confirm email field: {e}")
                result["error"] = f"Failed at confirm email field: {str(e)}"
                return result

            # Title (optional)
            if report_data.get("title"):
                try:
                    # Adding a small delay before moving to the next field
                    time.sleep(1)
                    title_field = self.wait.until(
                        EC.element_to_be_clickable((By.NAME, "title"))
                    )
                    title_field.clear()
                    title_field.send_keys(report_data["title"])
                    print("✓ Title field filled")
                except Exception as e:
                    print(f"Warning: Could not fill title field: {e}")
                    # Continue anyway as this is optional

            # Company (optional)
            if report_data.get("company"):
                try:
                    time.sleep(1)
                    company_field = self.wait.until(
                        EC.element_to_be_clickable((By.NAME, "company"))
                    )
                    company_field.clear()
                    company_field.send_keys(report_data["company"])
                    print("✓ Company field filled")
                except Exception as e:
                    print(f"Warning: Could not fill company field: {e}")
                    # Continue anyway as this is optional

            # Telephone (optional)
            if report_data.get("telephone"):
                try:
                    time.sleep(1)
                    tele_field = self.wait.until(
                        EC.element_to_be_clickable((By.NAME, "tele"))
                    )
                    tele_field.clear()
                    tele_field.send_keys(report_data["telephone"])
                    print("✓ Telephone field filled")
                except Exception as e:
                    print(f"Warning: Could not fill telephone field: {e}")
                    # Continue anyway as this is optional

            # Evidence URLs
            try:
                time.sleep(1)
                urls_field = self.wait.until(
                    EC.element_to_be_clickable((By.NAME, "urls"))
                )
                urls_field.clear()

                # Format domain as URL
                formatted_domain = (
                    f"https://{domain}"
                    if not domain.startswith(("http://", "https://"))
                    else domain
                )
                urls_field.send_keys(formatted_domain)
                print("✓ URLs field filled")
            except Exception as e:
                print(f"Error filling URLs field: {e}")
                result["error"] = f"Failed at URLs field: {str(e)}"
                return result

            # Justification/Evidence
            try:
                time.sleep(1)
                justification_field = self.wait.until(
                    EC.element_to_be_clickable((By.NAME, "justification"))
                )
                justification_field.clear()
                justification_field.send_keys(report_data["justification"])
                print("✓ Justification field filled")
            except Exception as e:
                print(f"Error filling justification field: {e}")
                result["error"] = f"Failed at justification field: {str(e)}"
                return result

            # Targeted Brand (optional)
            if report_data.get("targeted_brand"):
                try:
                    time.sleep(1)
                    original_work_field = self.wait.until(
                        EC.element_to_be_clickable((By.NAME, "original_work"))
                    )
                    original_work_field.clear()
                    original_work_field.send_keys(report_data["targeted_brand"])
                    print("✓ Targeted brand field filled")
                except Exception as e:
                    print(f"Warning: Could not fill targeted brand field: {e}")
                    # Continue anyway as this is optional

            # Comments (optional)
            if report_data.get("comments"):
                try:
                    time.sleep(1)
                    comments_field = self.wait.until(
                        EC.element_to_be_clickable((By.NAME, "comments"))
                    )
                    comments_field.clear()
                    comments_field.send_keys(report_data["comments"])
                    print("✓ Comments field filled")
                except Exception as e:
                    print(f"Warning: Could not fill comments field: {e}")
                    # Continue anyway as this is optional

            # Check the appropriate boxes - finding all checkboxes that aren't readonly
            # The 1st and 3rd checkboxes are readonly and should already be checked
            try:
                time.sleep(1)
                # Get all checkboxes that are not readonly
                checkboxes = self.driver.find_elements(
                    By.CSS_SELECTOR, "input[type='checkbox']:not([readonly])"
                )
                print(f"Found {len(checkboxes)} non-readonly checkboxes")

                # Include contact info with reports? (2nd and 4th checkboxes)
                if report_data.get("include_contact_info", False):
                    for i, checkbox in enumerate(checkboxes):
                        if i < 2:  # Only the first two non-readonly checkboxes
                            if not checkbox.is_selected():
                                time.sleep(1)
                                # Check if checkbox text contains "website owner", sibling span element includes text
                                span_text = checkbox.find_element(
                                    By.XPATH, "./following-sibling::span"
                                ).text
                                # We don't want them to be notified as they are the scammers.
                                if not "website owner" in span_text.lower():
                                    self.driver.execute_script(
                                        "arguments[0].click();", checkbox
                                    )
                                    print(f"✓ Contact info checkbox {i+1} checked")

                # DSA certification checkbox (last one)
                dsa_checkbox = checkboxes[-1]
                if not dsa_checkbox.is_selected():
                    time.sleep(1)
                    self.driver.execute_script("arguments[0].click();", dsa_checkbox)
                    print("✓ DSA certification checkbox checked")
            except Exception as e:
                print(f"Error handling checkboxes: {e}")
                result["error"] = f"Failed at checkbox selection: {str(e)}"
                return result

            # First try to detect if there's a turnstile widget
            print("Checking for Cloudflare Turnstile widget...")
            turnstile_frame = None
            human_intervention_needed = False

            # Look for Turnstile iframe
            try:
                # Use XPath to find Cloudflare Turnstile iframe
                iframe_xpath = "//iframe[contains(@src, 'challenges.cloudflare.com')]"
                turnstile_frames = self.driver.find_elements(By.XPATH, iframe_xpath)

                if turnstile_frames:
                    turnstile_frame = turnstile_frames[
                        0
                    ]  # Assume the first one is the challenge

                if turnstile_frame:
                    print("✓ Turnstile widget detected. Attempting automated bypass...")

                    # Switch to the Turnstile iframe
                    self.driver.switch_to.frame(turnstile_frame)

                    # Wait for challenge to load
                    time.sleep(2)

                    # Look for challenge elements
                    try:
                        challenge_element = self.driver.find_element(
                            By.CSS_SELECTOR, "div.challenge"
                        )
                        self.driver.execute_script(
                            "arguments[0].click();", challenge_element
                        )
                        print("✓ Clicked Turnstile challenge element")
                    except Exception:
                        try:
                            checkbox = self.driver.find_element(
                                By.CSS_SELECTOR, "span.mark"
                            )
                            self.driver.execute_script(
                                "arguments[0].click();", checkbox
                            )
                            print("✓ Clicked Turnstile checkbox element")
                        except Exception:
                            print(
                                "⨯ Unable to find clickable elements in Turnstile. Trying alternative methods."
                            )

                    # Return to main frame
                    self.driver.switch_to.default_content()

                    # Alternative Method 1: Tab-based navigation and Enter key
                    try:
                        body = self.driver.find_element(By.TAG_NAME, "body")

                        for _ in range(5):  # Try navigating to the challenge
                            body.send_keys(Keys.TAB)
                            time.sleep(0.5)

                        body.send_keys(Keys.ENTER)
                        print("✓ Sent TAB navigation and ENTER key")
                        time.sleep(2)
                    except Exception as e:
                        print(f"⨯ Tab navigation error: {e}")

                    # Wait a bit to see if bypass worked
                    time.sleep(5)

                    # Check if the submit button is enabled
                    try:
                        submit_button = self.driver.find_element(
                            By.CSS_SELECTOR, "button[type='submit']"
                        )
                        if not submit_button.get_attribute("disabled"):
                            print("✓ Bypass successful! Submit button is enabled.")
                            human_intervention_needed = False
                        else:
                            print(
                                "⨯ Automated bypass failed. Human intervention required."
                            )
                            human_intervention_needed = True
                    except Exception:
                        print("⨯ Could not check submit button status.")
                        human_intervention_needed = True

                else:
                    print("⨯ No Turnstile widget detected. Proceeding with submission.")
                    human_intervention_needed = False

            except Exception as e:
                print(f"Error checking for turnstile: {e}")
                human_intervention_needed = True

            # If human intervention is needed, prompt the user
            if human_intervention_needed:
                print("=" * 80)
                print(
                    f"HUMAN INTERVENTION REQUIRED - Please solve the captcha in the browser window"
                )
                print(f"Report #{result['report_number']} - Reporting domain: {domain}")
                print("=" * 80)

            # Wait for the captcha to be solved (submit button becomes enabled)
            max_wait_time = 300  # 5 minutes to solve the captcha
            wait_time = 0
            step = 5

            submit_button = None

            while wait_time < max_wait_time:
                try:
                    submit_button = self.driver.find_element(
                        By.CSS_SELECTOR, "button[type='submit']"
                    )
                    if not submit_button.get_attribute("disabled"):
                        # Button is enabled, captcha has been solved
                        print("Submit button is enabled, proceeding with submission...")

                        # Click the submit button
                        self.driver.execute_script(
                            "arguments[0].click();", submit_button
                        )

                        # Wait for confirmation or error message
                        time.sleep(5)

                        # Check for success (can be adjusted based on Cloudflare's actual confirmation page)
                        if (
                            "thank you" in self.driver.page_source.lower()
                            or "report submitted" in self.driver.page_source.lower()
                        ):
                            result["success"] = True
                            print(
                                f"✓ Report #{result['report_number']} for {domain} submitted successfully!"
                            )

                            # Save cookies after successful submission
                            self.save_cookies()

                            # If we got here and previously bypassed the captcha, set the flag
                            if not human_intervention_needed:
                                self.previously_bypassed_captcha = True
                        else:
                            result["error"] = (
                                "Form submitted but no confirmation detected"
                            )
                            print(
                                f"Warning: Form submitted but couldn't confirm success"
                            )

                        break
                except Exception as e:
                    print(f"Error checking submit button: {e}")

                # Wait a bit before checking again
                time.sleep(step)
                wait_time += step
                if (
                    human_intervention_needed and wait_time % 30 == 0
                ):  # Reminder every 30 seconds
                    print(
                        f"Still waiting for captcha solution... ({wait_time} seconds elapsed)"
                    )

            if wait_time >= max_wait_time:
                result["error"] = "Timed out waiting for form submission"
                print("⨯ Timed out waiting for form to be submitted")

            # Ensure we don't move to the next domain until this one completes
            if not result["success"] and not result["error"]:
                result["error"] = (
                    "Process didn't complete but no specific error detected"
                )

            # Increment report counter
            self.report_counter += 1

            # Return result
            return result

        except Exception as e:
            result["error"] = str(e)
            print(f"⨯ Error submitting report for {domain}: {result['error']}")
            return result

    def save_cookies(self):
        """Save cookies to file for reuse in future sessions"""
        try:
            cookies = self.driver.get_cookies()
            local_storage = self.driver.execute_script(
                "return Object.keys(localStorage)"
            )
            local_storage_dict = {}

            # Get all local storage items
            for key in local_storage:
                value = self.driver.execute_script(
                    f"return localStorage.getItem('{key}')"
                )
                local_storage_dict[key] = value

            # Save both cookies and local storage
            data_to_save = {
                "cookies": cookies,
                "local_storage": local_storage_dict,
                "session_tokens": self.session_tokens,
            }

            with open(self.cookie_file, "wb") as f:
                pickle.dump(data_to_save, f)
            print(f"Session data saved to {self.cookie_file}")
        except Exception as e:
            print(f"Error saving cookies: {e}")

    def load_cookies(self):
        """Load cookies from file if exists"""
        try:
            if os.path.exists(self.cookie_file):
                # First visit cloudflare domain to set cookies for that domain
                self.driver.get(self.cloudflare_url)
                time.sleep(2)

                with open(self.cookie_file, "rb") as f:
                    data = pickle.load(f)

                # Restore cookies
                for cookie in data.get("cookies", []):
                    # Some cookies can't be loaded if they've expired
                    try:
                        self.driver.add_cookie(cookie)
                    except Exception:
                        pass

                # Restore local storage
                for key, value in data.get("local_storage", {}).items():
                    self.driver.execute_script(
                        f"localStorage.setItem('{key}', '{value}')"
                    )

                # Restore session tokens
                self.session_tokens = data.get("session_tokens", {})

                # Refresh the page to apply cookies
                self.driver.refresh()
                print("Previous session data loaded successfully")
                return True
        except Exception as e:
            print(f"Error loading cookies: {e}")
        return False

    def close(self):
        """Close browser when done"""
        try:
            # Save cookies before closing
            self.save_cookies()

            if hasattr(self, "driver") and self.driver:
                self.driver.quit()
                print("Browser closed successfully")
        except Exception as e:
            print(f"Error closing browser: {e}")


def load_domains_from_file(domains_file: str) -> List[str]:
    """
    Load domains from a CSV or TXT file.

    Args:
        domains_file: Path to CSV or TXT file with domains

    Returns:
        List of domain strings
    """
    domains = []
    file_ext = os.path.splitext(domains_file)[1].lower()

    # TODO: this is such AI slop code, blargh
    if file_ext == ".csv":
        # Load from CSV
        with open(domains_file, "r") as f:
            if "," in f.readline():  # Check if it's comma-separated
                # Reset file pointer
                f.seek(0)
                reader = csv.reader(f)
                next(reader, None)  # Skip header
                for row in reader:
                    if row and len(row) > 0:
                        domain = (
                            row[1] if len(row) > 1 else row[0]
                        )  # Use second column if available
                        domains.append(domain.strip())
            else:
                # If it's not comma-separated, treat as single column
                f.seek(0)
                next(f, None)  # Skip header
                domains = [line.strip() for line in f if line.strip()]
    else:
        # Load from TXT
        with open(domains_file, "r") as f:
            domains = [line.strip() for line in f if line.strip()]

    return domains


def batch_submit_reports(
    domains_file: str,
    output_file: str = "report_results.json",
    report_data: Dict = None,
    batch_size: int = 50,
    headless: bool = False,
    timeout: int = 20,
    skip_lines: int = 0,
    cookie_file: str = None,
) -> None:
    """
    Submit individual reports for each domain in sequence.

    Args:
        domains_file: Path to CSV or TXT file with domains
        output_file: File to save report results
        report_data: Dictionary with report information
        batch_size: Number of domains to process in sequence (each as a separate report)
        headless: Whether to run browser in headless mode
        timeout: Timeout for page loads in seconds
        skip_lines: Number of lines to skip in the input file
    """
    if report_data is None:
        # Default report data - REPLACE WITH YOUR INFORMATION
        report_data = {
            "name": "Your Name",
            "email": "your.email@example.com",
            "title": "Security Researcher",  # Optional
            "company": "Your Company",  # Optional
            "telephone": "123-456-7890",  # Optional
            "justification": """
This domain is part of an active phishing campaign targeting customers of [BRAND].
The site is designed to steal login credentials and personal information.

Evidence of phishing:
1. The domain uses similar naming patterns to [BRAND]
2. It hosts fake login pages that mimic [BRAND]'s legitimate site
3. User-entered data is sent to attackers
            """,
            "targeted_brand": "https://legitimate-brand.com",  # The brand being impersonated
            "comments": "Part of a coordinated phishing campaign detected on [DATE]",  # Optional
            "include_contact_info": True,  # Whether to include your contact info with forwarded reports
        }

    try:
        # Load domains
        domains = load_domains_from_file(domains_file)

        # Skip lines if needed
        if skip_lines > 0:
            domains = domains[skip_lines:]

        print(f"Loaded {len(domains)} domains from {domains_file}")
        print(f"Each domain will be submitted as a separate report")

        # Initialize reporter
        reporter = CloudflareReporter(
            batch_size=batch_size,
            headless=headless,
            timeout=timeout,
            cookie_file=cookie_file,
        )

        all_results = []

        try:
            # Process each domain individually
            for i, domain in enumerate(domains):
                print(f"Processing domain {i+1}/{len(domains)}: {domain}")

                # Submit report for this individual domain
                result = reporter.report_domain(domain, report_data)
                all_results.append(result)

                # Save interim results
                with open(output_file, "w") as f:
                    json.dump(all_results, f, indent=2)

                # Wait between reports
                if i < len(domains) - 1:
                    wait_time = random.randint(30, 60)
                    print(f"Waiting {wait_time} seconds before next report...")
                    time.sleep(wait_time)

        finally:
            reporter.close()

        # Final save
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2)

        # Print summary
        successful = sum(1 for r in all_results if r["success"])
        print(
            f"Report Summary: {successful}/{len(domains)} reports submitted successfully"
        )
        print(f"Results saved to {output_file}")

    except Exception as e:
        print(f"Error processing domains: {e}")
