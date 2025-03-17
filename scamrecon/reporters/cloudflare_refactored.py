"""
Refactored Cloudflare Abuse Reporter with improved architecture.
This version replaces the original and simplifies the code using shared utilities.
"""

import json
import os
import random
import time
from typing import Dict, List, Optional, Tuple, Union, Any

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# Import shared utilities
from scamrecon.utils.browser import BrowserManager
from scamrecon.utils.form_utils import extract_form_fields, fill_form, wait_for_form_validation
from scamrecon.utils.error_handler import ErrorHandler
from scamrecon.utils.domain_utils import normalize_domain

# Import the TurnstileClient
from scamrecon.reporters.utils.turnstile_client import TurnstileClient


class CloudflareReporter:
    """
    Submits phishing reports to Cloudflare's abuse portal with enhanced anti-detection.
    This refactored version uses shared utilities for improved maintainability.
    """

    def __init__(
        self,
        output_dir: str = "reports",
        timeout: int = 30,
        headless: bool = False,
        batch_size: int = 50,
        cookie_file: Optional[str] = None,
        profile_dir: Optional[str] = None,
        turnstile_api_url: str = "http://127.0.0.1:5000",
        use_turnstile_api: bool = True,
        evidence_dir: Optional[str] = None,
    ):
        """
        Initialize the reporter with improved settings.

        Args:
            output_dir: Directory to save report logs
            timeout: Page load timeout in seconds
            headless: Whether to run browser in headless mode
            batch_size: Number of domains to process (each as an individual report)
            cookie_file: Path to cookie file for persistent sessions
            profile_dir: Path to Chrome profile directory
            turnstile_api_url: URL of the Turnstile Solver API
            use_turnstile_api: Whether to use the Turnstile Solver API
            evidence_dir: Directory containing investigation evidence files
        """
        # Initialize settings
        self.output_dir = output_dir
        self.timeout = timeout
        self.headless = headless
        self.batch_size = batch_size
        self.cookie_file = cookie_file
        self.profile_dir = profile_dir
        self.cloudflare_url = "https://abuse.cloudflare.com/phishing"
        self.turnstile_api_url = turnstile_api_url
        self.use_turnstile_api = use_turnstile_api
        self.evidence_dir = evidence_dir

        # Setup error handler
        self.error_handler = ErrorHandler(logger_name="CloudflareReporter")
        self.log = self.error_handler.log

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Create evidence reports directory if specified
        if self.evidence_dir:
            os.makedirs(os.path.join(self.evidence_dir, "reports"), exist_ok=True)
            self.log(f"Evidence directory set to {self.evidence_dir}")

        # Initialize Turnstile client if enabled
        if self.use_turnstile_api:
            self.turnstile_client = TurnstileClient(api_url=turnstile_api_url)
            # Check if API is available
            if not self.turnstile_client.is_api_available():
                self.log(
                    f"Turnstile API at {turnstile_api_url} is not available. "
                    "Please start the API server with 'scamrecon api' or set use_turnstile_api=False.",
                    "warning"
                )
                self.use_turnstile_api = False

        # Initialize browser manager
        self.browser = BrowserManager(
            headless=headless,
            timeout=timeout,
            cookie_file=cookie_file,
            profile_dir=profile_dir
        )

        # Report counter for logging
        self.report_counter = 0

    def handle_captcha(self, max_wait_time: int = 600) -> bool:
        """
        Handle Turnstile captcha with improved detection of completion.
        If the Turnstile API is available, use it; otherwise, fallback to human solving.

        Args:
            max_wait_time: Maximum time to wait for human to solve captcha

        Returns:
            bool: True if captcha solved, False otherwise
        """
        # First try to find the Turnstile sitekey on the page
        try:
            page_source = self.browser.driver.page_source

            # Check if we can find response fields with sitekey attribute
            sitekey = None
            response_fields = self.browser.driver.find_elements(
                By.CSS_SELECTOR,
                ".cf-turnstile, [data-sitekey], [class*='turnstile'], [class*='cf-']",
            )

            for field in response_fields:
                try:
                    potential_sitekey = field.get_attribute("data-sitekey")
                    if potential_sitekey and len(potential_sitekey) > 10:
                        sitekey = potential_sitekey
                        break
                except:
                    pass

            # If we couldn't find it in elements, try regex on page source
            if not sitekey and self.use_turnstile_api:
                sitekey = self.turnstile_client.extract_sitekey(page_source)

            # If we have a sitekey and the API is enabled, use it
            if sitekey and self.use_turnstile_api:
                self.log(f"Found Turnstile sitekey: {sitekey}", "info")
                print("\n" + "=" * 80)
                print(f"TURNSTILE DETECTED - Using API to solve")
                print(f"Sitekey: {sitekey}")
                print("=" * 80 + "\n")

                # Get the current URL
                current_url = self.browser.driver.current_url

                # Call the API to solve the turnstile
                result = self.turnstile_client.solve(
                    url=current_url, sitekey=sitekey, timeout=max_wait_time
                )

                if result["status"] == "success" and result["token"]:
                    # We got a token, inject it into the page
                    token = result["token"]
                    self.log(f"Injecting token: {token[:10]}...", "info")

                    # Create JavaScript to inject the token into all possible fields
                    inject_js = f"""
                    (function() {{
                        // Find all possible turnstile token fields and set their value
                        const fieldSelectors = [
                            'input[name="cf-turnstile-response"]',
                            'input[name="g-recaptcha-response"]',
                            'input[name="cf_challenge_response"]',
                            '[data-cf-response]',
                            '[data-cf-turnstile-response]'
                        ];
                        
                        let injected = false;
                        fieldSelectors.forEach(selector => {{
                            const fields = document.querySelectorAll(selector);
                            fields.forEach(field => {{
                                field.value = "{token}";
                                injected = true;
                                console.log("Injected Turnstile token into field", field);
                            }});
                        }});
                        
                        // Set to window and document variables as fallback
                        window.turnstileToken = "{token}";
                        document.turnstileToken = "{token}";
                        
                        // Store in multiple places for redundancy
                        if (typeof turnstile !== 'undefined') {{
                            if (typeof turnstile.execute === 'function') {{
                                try {{
                                    turnstile.execute = function() {{ return "{token}"; }};
                                }} catch(e) {{}}
                            }}
                        }}
                        
                        // Enable submit button if it was disabled
                        const submitButtons = document.querySelectorAll('button[type="submit"], input[type="submit"]');
                        submitButtons.forEach(button => {{
                            if (button.hasAttribute('disabled')) {{
                                button.removeAttribute('disabled');
                                injected = true;
                                console.log("Enabled submit button", button);
                            }}
                        }});
                        
                        return injected;
                    }})();
                    """

                    # Execute the JavaScript
                    injected = self.browser.driver.execute_script(inject_js)

                    if injected:
                        self.log("Successfully injected Turnstile token", "success")
                        # Give a brief pause for the page to process the token
                        time.sleep(2)
                        return True
                    else:
                        self.log(
                            "Failed to find fields to inject token, falling back to human solving",
                            "warning"
                        )
                else:
                    error_msg = result.get("message", "Unknown error")
                    self.log(f"API failed to solve Turnstile: {error_msg}", "warning")
                    self.log("Falling back to human solving...", "info")
        except Exception as e:
            self.error_handler.handle_exception(e, "Error using Turnstile API")
            self.log("Falling back to human solving...", "info")

        # Fallback to human solving
        print("\n" + "=" * 80)
        print("HUMAN CAPTCHA REQUIRED - Please solve the captcha in the browser window")
        print("Take your time - you have 10 minutes before timeout")
        print(
            "Note: Once you solve the captcha, wait for the submit button to become enabled"
        )
        print("=" * 80 + "\n")

        # Check if submit button becomes enabled or if response field gets populated
        def is_captcha_solved():
            try:
                # Primary check: submit button enabled
                submit_button = self.browser.driver.find_element(
                    By.CSS_SELECTOR, "button[type='submit']"
                )
                if not submit_button.get_attribute("disabled"):
                    return True

                # Backup check: response field populated
                response_fields = self.browser.driver.find_elements(
                    By.CSS_SELECTOR,
                    "input[name='cf-turnstile-response'], input[name='g-recaptcha-response']",
                )
                for field in response_fields:
                    if field.get_attribute("value") and len(field.get_attribute("value")) > 10:
                        return True

                # Additional check: look for success indicators in the page
                page_text = self.browser.driver.page_source.lower()
                success_indicators = [
                    "captcha passed",
                    "verification complete",
                    "challenge complete",
                ]
                for indicator in success_indicators:
                    if indicator in page_text:
                        return True
            except Exception:
                pass
            return False

        # Use progressive wait strategy
        return self.browser.wait_with_progressive_checks(
            is_captcha_solved,
            initial_check=5,
            max_wait=max_wait_time,
            message="Waiting for human to solve captcha",
        )

    def report_domain(self, domain: str, report_data: Dict) -> Dict:
        """
        Submit a report for a single domain with improved anti-detection.

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
            self.log(f"\nProcessing report #{result['report_number']} for domain: {domain}", "info")

            # Make sure we have a driver instance
            if not self.browser.driver:
                self.browser.setup_driver()

            # Visit a neutral site first to initialize browser state
            self.browser.navigate_to("https://example.org")

            # Load the form with retry logic
            retry_count = 0
            max_retries = 3
            form_loaded = False

            while retry_count < max_retries and not form_loaded:
                try:
                    self.log(
                        f"Loading Cloudflare abuse form (attempt {retry_count+1}/{max_retries})",
                        "info"
                    )

                    # Navigate to the form
                    self.browser.navigate_to(self.cloudflare_url)

                    # Wait for form with improved detection
                    WebDriverWait(self.browser.driver, 15).until(
                        EC.presence_of_element_located((By.TAG_NAME, "form"))
                    )

                    self.log("Form detected on page", "success")
                    form_loaded = True

                except Exception as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        result["error"] = "Could not load form after multiple attempts"
                        self.error_handler.handle_exception(e, "Form loading failed")
                        return result

                    self.log("Timeout loading form, retrying...", "warning")
                    time.sleep(random.uniform(3.0, 5.0))

            # Add some natural browser behavior - scroll slightly
            self.browser.driver.execute_script(
                f"window.scrollBy(0, {random.randint(50, 150)});"
            )
            time.sleep(random.uniform(1.0, 2.0))

            # Fill form fields automatically using the form_utils module
            self.log("Filling form fields with natural timing...", "info")

            # Prepare form data with domain-specific information
            formatted_domain = (
                f"https://{domain}"
                if not domain.startswith(("http://", "https://"))
                else domain
            )

            # If field exists in report_data, use it; otherwise, use default
            form_data = {
                "name": report_data.get("name", ""),
                "email": report_data.get("email", ""),
                "email2": report_data.get("email", ""),  # Confirmation email
                "title": report_data.get("title", ""),
                "company": report_data.get("company", ""),
                "tele": report_data.get("telephone", ""),
                "urls": formatted_domain,
                "justification": report_data.get("justification", ""),
                "original_work": report_data.get("targeted_brand", ""),
                "comments": report_data.get("comments", ""),
            }

            # Fill the form fields
            fill_results = fill_form(self.browser.driver, form_data, natural_typing=True)
            
            # Check if critical fields were filled
            critical_fields = ["name", "email", "email2", "urls", "justification"]
            for field in critical_fields:
                if field in fill_results and not fill_results[field]:
                    result["error"] = f"Failed to fill {field} field"
                    return result

            # Scroll down to checkboxes
            self.browser.driver.execute_script(
                f"window.scrollBy(0, {random.randint(200, 300)});"
            )
            time.sleep(random.uniform(1.0, 1.5))

            # Handle checkboxes with natural timing
            try:
                # Get all checkboxes that are not readonly
                checkboxes = self.browser.driver.find_elements(
                    By.CSS_SELECTOR, "input[type='checkbox']:not([readonly])"
                )
                self.log(f"Found {len(checkboxes)} non-readonly checkboxes", "debug")

                # Include contact info with reports? (first two non-readonly checkboxes)
                if report_data.get("include_contact_info", False):
                    for i, checkbox in enumerate(checkboxes):
                        if i < 2:  # Only the first two non-readonly checkboxes
                            if not checkbox.is_selected():
                                # Check span text to ensure it's not the "website owner" option
                                try:
                                    span = checkbox.find_element(
                                        By.XPATH, "./following-sibling::span"
                                    )
                                    span_text = span.text.lower()

                                    if "website owner" not in span_text:
                                        # Natural pause before clicking
                                        time.sleep(random.uniform(0.5, 1.0))
                                        self.browser.natural_click(checkbox)
                                        self.log(f"Contact info checkbox {i+1} checked", "debug")

                                except Exception as e:
                                    self.log(f"Warning: Error checking checkbox text: {e}", "warning")

                # DSA certification checkbox (last one) - always check this
                dsa_checkbox = checkboxes[-1]
                if not dsa_checkbox.is_selected():
                    # Scroll to make sure it's visible
                    self.browser.driver.execute_script(
                        "arguments[0].scrollIntoView({block: 'center', behavior: 'smooth'});",
                        dsa_checkbox,
                    )
                    time.sleep(random.uniform(0.7, 1.2))

                    # Natural click
                    self.browser.natural_click(dsa_checkbox)
                    self.log("DSA certification checkbox checked", "debug")

            except Exception as e:
                self.error_handler.handle_exception(e, "Error handling checkboxes")
                result["error"] = f"Failed at checkbox selection: {str(e)}"
                return result

            # Wait for human to solve the captcha with extended time
            if not self.handle_captcha(max_wait_time=600):
                result["error"] = "Timed out waiting for captcha solution"
                self.log("Timed out waiting for captcha to be solved", "error")
                return result

            # Find and click the submit button
            try:
                submit_button = WebDriverWait(self.browser.driver, 10).until(
                    EC.element_to_be_clickable(
                        (By.CSS_SELECTOR, "button[type='submit']")
                    )
                )
                self.log("Submit button is enabled, proceeding with submission...", "info")

                # Natural pause before clicking submit
                time.sleep(random.uniform(0.8, 1.5))

                # Click with natural movement
                self.browser.natural_click(submit_button)
                self.log("Clicked submit button", "debug")

                # Wait for confirmation with improved detection
                def is_submission_successful():
                    try:
                        page_text = self.browser.driver.page_source.lower()
                        success_indicators = [
                            "thank you",
                            "report submitted",
                            "received",
                            "confirmation",
                            "successfully submitted",
                        ]
                        for indicator in success_indicators:
                            if indicator in page_text:
                                return True
                        return False
                    except:
                        return False

                # Wait for success indication
                submission_success = self.browser.wait_with_progressive_checks(
                    is_submission_successful,
                    initial_check=1,
                    max_wait=20,
                    message="Waiting for submission confirmation",
                )

                if submission_success:
                    result["success"] = True
                    self.log(
                        f"Report #{result['report_number']} for {domain} submitted successfully!",
                        "success"
                    )

                    # Save cookies after successful submission
                    if self.cookie_file:
                        self.browser.save_cookies()
                else:
                    result["error"] = "Form submitted but no confirmation detected"
                    self.log("Form submitted but couldn't confirm success", "warning")

            except Exception as e:
                self.error_handler.handle_exception(e, "Error during form submission")
                result["error"] = f"Error during form submission: {str(e)}"

            # Increment report counter
            self.report_counter += 1

            # Add natural delay after submission before next domain
            time.sleep(random.uniform(2.0, 4.0))

            return result

        except Exception as e:
            self.error_handler.handle_exception(e, f"Error submitting report for {domain}")
            result["error"] = str(e)
            return result

    def close(self):
        """Close the browser when done"""
        if hasattr(self, "browser"):
            self.browser.close()


# Additional helper function that was previously duplicated
def batch_submit_reports(
    domains_file: str,
    output_file: str = "report_results.json",
    report_data: Optional[Dict] = None,
    batch_size: int = 50,
    headless: bool = False,
    timeout: int = 20,
    skip_lines: int = 0,
    cookie_file: Optional[str] = None,
    profile_dir: Optional[str] = None,
    turnstile_api_url: str = "http://127.0.0.1:5000",
    use_turnstile_api: bool = True,
    evidence_dir: Optional[str] = None,
):
    """
    Submit individual reports for each domain using our improved CloudflareReporter.
    
    Args:
        domains_file: File containing domains to report (CSV or TXT)
        output_file: File to save results to
        report_data: Dictionary containing report information
        batch_size: Number of domains to process in a batch
        headless: Whether to run browser in headless mode
        timeout: Page load timeout in seconds
        skip_lines: Number of lines to skip from the input file
        cookie_file: File to store/load session cookies
        profile_dir: Path to Chrome profile directory
        turnstile_api_url: URL of the Turnstile Solver API
        use_turnstile_api: Whether to use the Turnstile Solver API
        evidence_dir: Directory containing investigation evidence files
    """
    # Import required modules
    import json
    from rich.console import Console
    from scamrecon.utils.domain_utils import load_domains_from_file

    console = Console()
    error_handler = ErrorHandler(logger_name="batch_submit_reports")

    try:
        # Load domains
        domains = load_domains_from_file(domains_file)

        # Skip lines if needed
        if skip_lines > 0 and skip_lines < len(domains):
            domains = domains[skip_lines:]

        console.print(f"[bold]Loaded {len(domains)} domains from {domains_file}[/bold]")
        console.print(
            f"[bold]Each domain will be submitted as a separate report[/bold]"
        )
        
        # Check if Turnstile API is available
        if use_turnstile_api:
            from scamrecon.reporters.utils.turnstile_client import TurnstileClient
            client = TurnstileClient(api_url=turnstile_api_url)
            if not client.is_api_available():
                console.print(
                    f"[yellow]Warning: Turnstile API at {turnstile_api_url} is not available.[/yellow]"
                )
                console.print(
                    f"[yellow]You can start it with 'scamrecon api'. Falling back to human captcha solving.[/yellow]"
                )
                use_turnstile_api = False
            else:
                console.print(
                    f"[green]Using Turnstile API at {turnstile_api_url} for automated captcha solving[/green]"
                )

        # Initialize reporter
        reporter = CloudflareReporter(
            batch_size=batch_size,
            headless=headless,
            timeout=timeout,
            cookie_file=cookie_file,
            profile_dir=profile_dir,
            turnstile_api_url=turnstile_api_url,
            use_turnstile_api=use_turnstile_api,
            evidence_dir=evidence_dir,
        )

        all_results = []

        try:
            # Process each domain individually
            for i, domain in enumerate(domains):
                console.print(
                    f"\n[cyan]Processing domain {i+1}/{len(domains)}: {domain}[/cyan]"
                )

                # Use report_data as is
                domain_report_data = report_data.copy() if report_data else {}

                # Check for domain-specific report data in evidence_dir
                if evidence_dir:
                    cloudflare_report_path = os.path.join(evidence_dir, f"{domain}_cloudflare_report.json")
                    if os.path.exists(cloudflare_report_path):
                        try:
                            with open(cloudflare_report_path, "r") as f:
                                cloudflare_report = json.load(f)
                                console.print(f"[green]Found direct cloudflare report for {domain}[/green]")
                                # Override with domain-specific data
                                domain_report_data.update(cloudflare_report)
                        except Exception as e:
                            console.print(f"[yellow]Error loading cloudflare report: {str(e)}[/yellow]")

                # Submit report for this individual domain
                result = reporter.report_domain(domain, domain_report_data)
                all_results.append(result)

                # Save interim results
                with open(output_file, "w") as f:
                    json.dump(all_results, f, indent=2)

        finally:
            reporter.close()

        # Final save
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2)

        # Print summary
        successful = sum(1 for r in all_results if r["success"])
        console.print(
            f"\n[bold green]Report Summary: {successful}/{len(domains)} reports submitted successfully[/bold green]"
        )

    except Exception as e:
        error_handler.handle_exception(e, "Error processing domains", reraise=True)