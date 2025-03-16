"""
Simplified Cloudflare Abuse Reporter optimized for reliability.
Focuses on consistent patterns that work rather than comprehensive anti-detection.
"""

import os
import pickle
import random
import time
from typing import Dict, Optional

import undetected_chromedriver as uc
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class CloudflareReporter:
    """
    Submits phishing reports to Cloudflare's abuse portal.
    Simplified for maximum reliability rather than comprehensive anti-detection.
    """

    def __init__(
        self,
        output_dir: str = "reports",
        timeout: int = 30,
        headless: bool = False,
        batch_size: int = 50,
        cookie_file: Optional[str] = None,
    ):
        """Initialize the reporter with minimal required settings"""
        self.output_dir = output_dir
        self.timeout = timeout
        self.headless = headless
        self.batch_size = batch_size
        self.cloudflare_url = "https://abuse.cloudflare.com/phishing"
        self.cookie_file = cookie_file

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Report counter
        self.report_counter = 0

        # Driver is initialized only when needed to avoid persistent fingerprinting
        self.driver = None

    def setup_driver(self):
        """Set up Chrome webdriver with minimal, proven settings"""
        # Close any existing driver to ensure a fresh session
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None

        options = uc.ChromeOptions()

        if self.headless:
            options.add_argument("--headless")

        # Minimal essential options - only what's proven to work
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")

        # Consistent window size - not too large, not too small
        options.add_argument("--window-size=1366,768")

        # Initialize the driver
        self.driver = uc.Chrome(options=options, use_subprocess=True)
        self.driver.set_page_load_timeout(self.timeout)

        # Apply basic anti-detection - keep this simple
        self.driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )

        # Load cookies if provided
        if self.cookie_file and os.path.exists(self.cookie_file):
            self.load_cookies()

        return self.driver

    def load_cookies(self):
        """Load cookies from file"""
        try:
            with open(self.cookie_file, "rb") as f:
                cookies = pickle.load(f)

            # Visit a dummy page first
            self.driver.get("https://example.com")
            time.sleep(2)

            # Add cookies
            for cookie in cookies:
                try:
                    self.driver.add_cookie(cookie)
                except:
                    pass  # Skip invalid cookies

            return True
        except Exception as e:
            print(f"Error loading cookies: {e}")
            return False

    def save_cookies(self):
        """Save cookies to file"""
        if not self.cookie_file:
            return False

        try:
            cookies = self.driver.get_cookies()
            os.makedirs(
                os.path.dirname(os.path.abspath(self.cookie_file)), exist_ok=True
            )
            with open(self.cookie_file, "wb") as f:
                pickle.dump(cookies, f)
            return True
        except Exception as e:
            print(f"Error saving cookies: {e}")
            return False

    def wait_for_element(
        self, selector, timeout=10, condition=EC.presence_of_element_located
    ):
        """Wait for an element using specified condition"""
        try:
            wait = WebDriverWait(self.driver, timeout)
            element = wait.until(condition(selector))
            return element
        except:
            return None

    def fill_field(self, field_name, value):
        """Fill a form field with simple delays"""
        try:
            field = self.wait_for_element(
                (By.NAME, field_name), condition=EC.element_to_be_clickable
            )

            if not field:
                print(f"Could not find field: {field_name}")
                return False

            # Clear and fill with moderate delay
            field.clear()
            time.sleep(random.uniform(0.3, 0.7))

            # Type with moderate delay
            field.send_keys(value)
            time.sleep(random.uniform(0.5, 1.0))

            return True
        except Exception as e:
            print(f"Error filling field {field_name}: {e}")
            return False

    def click_checkbox(self, checkbox):
        """Click a checkbox with JavaScript (more reliable)"""
        try:
            self.driver.execute_script(
                "arguments[0].scrollIntoView({block: 'center'});", checkbox
            )
            time.sleep(0.5)
            self.driver.execute_script("arguments[0].click();", checkbox)
            time.sleep(0.5)
            return True
        except Exception as e:
            print(f"Error clicking checkbox: {e}")
            return False

    def wait_for_captcha_solved(self, max_wait_time=600):
        """
        Wait for human to solve captcha
        Simplified to focus on reliable detection of completion
        """
        print("\n" + "=" * 80)
        print("HUMAN CAPTCHA REQUIRED - Please solve the captcha in the browser window")
        print(f"You have {max_wait_time//60} minutes to solve it")
        print("=" * 80 + "\n")

        start_time = time.time()

        while time.time() - start_time < max_wait_time:
            try:
                # Check if submit button is enabled (primary indicator)
                submit_button = self.driver.find_element(
                    By.CSS_SELECTOR, "button[type='submit']"
                )
                if not submit_button.get_attribute("disabled"):
                    print("Captcha appears to be solved - submit button is enabled!")
                    return True

                # Check for hidden response field (secondary indicator)
                response_fields = self.driver.find_elements(
                    By.CSS_SELECTOR,
                    "input[name='cf-turnstile-response'], input[name='g-recaptcha-response']",
                )
                for field in response_fields:
                    if (
                        field.get_attribute("value")
                        and len(field.get_attribute("value")) > 10
                    ):
                        print("Captcha appears to be solved - response token found!")
                        return True
            except:
                pass

            # Check every 5 seconds
            time.sleep(5)

            # Show regular updates
            elapsed = time.time() - start_time
            if int(elapsed) % 30 == 0:  # Every 30 seconds
                print(f"Still waiting for captcha solution... {int(elapsed)}s elapsed")

        print("Captcha wait time exceeded")
        return False

    def report_domain(self, domain: str, report_data: Dict) -> Dict:
        """
        Submit a report for a single domain with simplified approach
        focusing on reliability over comprehensive anti-detection
        """
        result = {
            "domain": domain,
            "success": False,
            "error": None,
            "report_number": self.report_counter + 1,
        }

        try:
            print(f"\n{'='*60}")
            print(f"Processing report #{result['report_number']} for domain: {domain}")
            print(f"{'='*60}")

            # Initialize fresh browser for each submission
            # This helps avoid detection from accumulated fingerprinting
            self.setup_driver()

            # Simple retry approach - often works better than sophisticated techniques
            for attempt in range(1, 4):  # Try up to 3 times
                print(f"Attempt {attempt} of 3")

                try:
                    # Load the form
                    print("Loading Cloudflare abuse form...")
                    self.driver.get(self.cloudflare_url)

                    # Wait for form to load
                    form = self.wait_for_element((By.TAG_NAME, "form"), timeout=15)
                    if not form:
                        print("Form not found, retrying...")
                        time.sleep(2)
                        continue

                    print("Form loaded successfully")

                    # Pause after page load - helps avoid detection
                    time.sleep(random.uniform(2.0, 3.0))

                    # ==== Fill form fields with simple approach ====
                    print("Filling form fields...")

                    # Basic user info
                    fields_to_fill = [
                        ("name", report_data["name"]),
                        ("email", report_data["email"]),
                        ("email2", report_data["email"]),
                    ]

                    # Optional fields
                    if report_data.get("title"):
                        fields_to_fill.append(("title", report_data["title"]))
                    if report_data.get("company"):
                        fields_to_fill.append(("company", report_data["company"]))
                    if report_data.get("telephone"):
                        fields_to_fill.append(("tele", report_data["telephone"]))

                    # Format domain
                    formatted_domain = (
                        f"https://{domain}"
                        if not domain.startswith(("http://", "https://"))
                        else domain
                    )

                    # Add content fields
                    fields_to_fill.extend(
                        [
                            ("urls", formatted_domain),
                            ("justification", report_data["justification"]),
                        ]
                    )

                    if report_data.get("targeted_brand"):
                        fields_to_fill.append(
                            ("original_work", report_data["targeted_brand"])
                        )
                    if report_data.get("comments"):
                        fields_to_fill.append(("comments", report_data["comments"]))

                    # Fill all fields with pauses between
                    for field_name, value in fields_to_fill:
                        if not self.fill_field(field_name, value):
                            print(f"Failed to fill {field_name} field")

                        # Pause between fields
                        time.sleep(random.uniform(0.5, 1.0))

                        # Occasionally scroll a bit
                        if random.random() < 0.3:
                            self.driver.execute_script(
                                f"window.scrollBy(0, {random.randint(50, 100)});"
                            )

                    # Scroll to bottom of form before checkboxes
                    self.driver.execute_script("window.scrollBy(0, 300);")
                    time.sleep(1)

                    # Handle checkboxes
                    print("Handling checkboxes...")
                    checkboxes = self.driver.find_elements(
                        By.CSS_SELECTOR, "input[type='checkbox']:not([readonly])"
                    )

                    if checkboxes:
                        # Contact info checkboxes
                        if report_data.get("include_contact_info", False):
                            for i, checkbox in enumerate(checkboxes):
                                if i < 2:  # First two checkboxes
                                    if not checkbox.is_selected():
                                        # Check if it's not the "website owner" checkbox
                                        span = checkbox.find_element(
                                            By.XPATH, "./following-sibling::span"
                                        )
                                        if "website owner" not in span.text.lower():
                                            self.click_checkbox(checkbox)
                                            print(f"Checked contact checkbox {i+1}")

                        # Always check the DSA certification checkbox (last one)
                        dsa_checkbox = checkboxes[-1]
                        if not dsa_checkbox.is_selected():
                            self.click_checkbox(dsa_checkbox)
                            print("Checked DSA certification checkbox")

                    # Wait for human to solve captcha with extended time
                    if not self.wait_for_captcha_solved(max_wait_time=600):
                        print("Failed to detect captcha solution")
                        result["error"] = "Captcha solution not detected"
                        break

                    # Wait for submit button to be clickable
                    submit_button = self.wait_for_element(
                        (By.CSS_SELECTOR, "button[type='submit']"),
                        condition=EC.element_to_be_clickable,
                    )

                    if not submit_button:
                        print("Submit button not found or not clickable")
                        result["error"] = "Submit button not found or not clickable"
                        break

                    # Click submit button
                    print("Clicking submit button...")
                    time.sleep(1)  # Small pause before clicking
                    self.driver.execute_script("arguments[0].click();", submit_button)

                    # Wait for confirmation
                    success = False
                    for _ in range(10):  # Try for 10 seconds
                        page_content = self.driver.page_source.lower()
                        if any(
                            term in page_content
                            for term in ["thank you", "report submitted", "received"]
                        ):
                            success = True
                            break
                        time.sleep(1)

                    if success:
                        result["success"] = True
                        result["error"] = None
                        print(f"✓ Successfully submitted report for {domain}!")

                        # Save cookies after successful submission
                        self.save_cookies()
                        break
                    else:
                        print("Form submitted but success not confirmed")
                        result["error"] = "Submission unconfirmed"

                except Exception as e:
                    print(f"Error during attempt {attempt}: {e}")
                    result["error"] = str(e)

                # If successful, no need for more attempts
                if result["success"]:
                    break

                # Wait between attempts
                if attempt < 3 and not result["success"]:
                    wait_time = 5 * attempt  # Progressive backoff
                    print(f"Waiting {wait_time} seconds before next attempt...")
                    time.sleep(wait_time)

            # Increment counter regardless of success
            self.report_counter += 1
            return result

        except Exception as e:
            result["error"] = str(e)
            print(f"Error reporting domain {domain}: {e}")
            return result
        finally:
            # Always close driver to release resources
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None

    def close(self):
        """Close the browser when done"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
            self.driver = None
