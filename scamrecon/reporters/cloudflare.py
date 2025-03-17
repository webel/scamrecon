"""
Enhanced Cloudflare Abuse Reporter with Turnstile-specific improvements.
Fixed for compatibility with all undetected_chromedriver versions.
"""

import json
import logging
import os
import pickle
import random
import time
from typing import Any, Callable, Dict, List, Optional, Union

import undetected_chromedriver as uc
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# Import the TurnstileClient
from scamrecon.reporters.utils.turnstile_client import TurnstileClient


class CloudflareReporter:
    """
    Submits phishing reports to Cloudflare's abuse portal with enhanced anti-detection.
    """

    def __init__(
        self,
        output_dir: str = "reports",
        timeout: int = 30,
        headless: bool = False,
        batch_size: int = 50,
        cookie_file: Optional[str] = None,
        turnstile_api_url: str = "http://127.0.0.1:5000",
        use_turnstile_api: bool = True,
        use_shared_browser: bool = True,
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
            turnstile_api_url: URL of the Turnstile Solver API
            use_turnstile_api: Whether to use the Turnstile Solver API
            use_shared_browser: Whether to share a browser instance with the turnstile API
            evidence_dir: Directory containing investigation evidence files
        """
        self.output_dir = output_dir
        self.timeout = timeout
        self.headless = headless
        self.batch_size = batch_size
        self.cloudflare_url = "https://abuse.cloudflare.com/phishing"
        self.cookie_file = cookie_file
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.turnstile_api_url = turnstile_api_url
        self.use_turnstile_api = use_turnstile_api
        self.use_shared_browser = use_shared_browser and use_turnstile_api
        self.evidence_dir = evidence_dir

        # Setup logging
        self.logger = logging.getLogger("CloudflareReporter")

        # Initialize Turnstile client if enabled
        if self.use_turnstile_api:
            self.turnstile_client = TurnstileClient(
                api_url=turnstile_api_url, shared_browser=self.use_shared_browser
            )
            # Check if API is available
            if not self.turnstile_client.is_api_available():
                self.logger.warning(
                    f"Turnstile API at {turnstile_api_url} is not available. "
                    "Please start the API server with 'scamrecon api' or set use_turnstile_api=False."
                )
                self.use_turnstile_api = False
                self.use_shared_browser = False

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Create evidence reports directory if specified
        if self.evidence_dir:
            os.makedirs(os.path.join(self.evidence_dir, "reports"), exist_ok=True)
            self.logger.info(f"Evidence directory set to {self.evidence_dir}")

        # Report counter for logging
        self.report_counter = 0

        # Setup driver with improved fingerprinting - only if not using shared browser
        if not self.use_shared_browser:
            self.setup_driver()

    def setup_driver(self):
        """Set up Chrome webdriver with enhanced anti-detection measures"""
        options = uc.ChromeOptions()

        if self.headless:
            options.add_argument("--headless")

        # Essential options
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        # Improved anti-detection
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument(f"user-agent={self.user_agent}")

        # Consistent window size for stable fingerprinting
        options.add_argument("--window-size=1280,800")

        # Use common language settings
        options.add_argument("--lang=en-US,en;q=0.9")

        # Disable WebRTC to prevent leaks
        options.add_argument("--disable-webrtc")

        # If we have a profile directory from a cookie file, use it
        if self.cookie_file and os.path.exists(self.cookie_file):
            try:
                with open(self.cookie_file, "rb") as f:
                    state_data = pickle.load(f)
                    if "profile_dir" in state_data:
                        profile_dir = state_data["profile_dir"]
                        if os.path.exists(profile_dir):
                            options.add_argument(f"--user-data-dir={profile_dir}")
                            print(f"Using existing Chrome profile: {profile_dir}")
            except Exception as e:
                print(f"Could not load profile directory from cookie file: {e}")

        # Initialize the driver with improved settings
        self.driver = uc.Chrome(options=options, use_subprocess=True)
        self.driver.set_page_load_timeout(self.timeout)
        self.driver.set_script_timeout(self.timeout)

        # Apply basic anti-detection JS after launch
        self._apply_stealth_js()

        # Wait setup with improved timeouts
        self.wait = WebDriverWait(self.driver, 10)

        # Load cookies if a cookie file is provided
        if self.cookie_file and os.path.exists(self.cookie_file):
            self.load_cookies()

    def _apply_stealth_js(self):
        """Apply anti-detection JavaScript after browser launch"""
        stealth_js = """
        // Remove automation flags
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
        
        // Mimic normal chrome
        window.chrome = {
            runtime: {},
            loadTimes: function() {},
            csi: function() {},
            app: {}
        };
        
        // Fix iframe detection
        const originalAttachShadow = Element.prototype.attachShadow;
        Element.prototype.attachShadow = function() {
            return originalAttachShadow.apply(this, arguments);
        };
        """

        # Execute the stealth script
        self.driver.execute_script(stealth_js)

    def load_cookies(self) -> bool:
        """
        Load cookies and browser state from file to maintain session.

        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.cookie_file, "rb") as f:
                state_data = pickle.load(f)

            # First visit a neutral domain to set cookies properly
            self.driver.get("https://example.com")
            time.sleep(2)

            # Add cookies
            if "cookies" in state_data:
                for cookie in state_data["cookies"]:
                    try:
                        self.driver.add_cookie(cookie)
                    except Exception as e:
                        print(f"Couldn't add cookie: {e}")

            # Set localStorage if available
            if "local_storage" in state_data:
                for key, value in state_data["local_storage"].items():
                    self.driver.execute_script(
                        f"localStorage.setItem('{key}', '{value}')"
                    )

            # Set sessionStorage if available
            if "session_storage" in state_data:
                for key, value in state_data["session_storage"].items():
                    self.driver.execute_script(
                        f"sessionStorage.setItem('{key}', '{value}')"
                    )

            print("✓ Session restored from previous profile")
            return True

        except Exception as e:
            print(f"Error loading browser state: {e}")
            return False

    def save_cookies(self) -> bool:
        """
        Save comprehensive browser state after successful submission.

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get cookies
            cookies = self.driver.get_cookies()

            # Get localStorage
            local_storage = {}
            local_storage_keys = self.driver.execute_script(
                "return Object.keys(localStorage)"
            )
            for key in local_storage_keys:
                value = self.driver.execute_script(
                    f"return localStorage.getItem('{key}')"
                )
                local_storage[key] = value

            # Get sessionStorage
            session_storage = {}
            session_storage_keys = self.driver.execute_script(
                "return Object.keys(sessionStorage)"
            )
            for key in session_storage_keys:
                value = self.driver.execute_script(
                    f"return sessionStorage.getItem('{key}')"
                )
                session_storage[key] = value

            # Save current profile directory if using one
            profile_dir = None
            chrome_options = self.driver.execute_script("return navigator.userAgent")

            # Save comprehensive state
            state_data = {
                "cookies": cookies,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "user_agent": self.user_agent,
                "profile_dir": profile_dir,
                "last_saved": time.time(),
            }

            with open(self.cookie_file, "wb") as f:
                pickle.dump(state_data, f)

            print(f"✓ Browser state saved to {self.cookie_file}")
            return True

        except Exception as e:
            print(f"Error saving browser state: {e}")
            return False

    def wait_with_progressive_checks(
        self,
        condition_func: Callable[[], bool],
        initial_check: int = 5,
        max_wait: int = 300,
        message: str = "Waiting...",
    ):
        """
        Wait with progressively longer intervals between checks.

        Args:
            condition_func: Function that returns True when condition is met
            initial_check: Initial check interval in seconds
            max_wait: Maximum wait time in seconds
            message: Message to show periodically

        Returns:
            True if condition was met, False on timeout
        """
        elapsed = 0
        check_interval = initial_check

        while elapsed < max_wait:
            try:
                if condition_func():
                    return True
            except Exception:
                pass  # Ignore exceptions during condition check

            time.sleep(check_interval)
            elapsed += check_interval

            # Report progress every ~30 seconds
            if elapsed % 30 < check_interval:
                print(f"{message} ({elapsed}s elapsed, {max_wait-elapsed}s remaining)")

            # Increase check interval progressively (but not too much)
            if check_interval < 15:
                check_interval = min(check_interval * 1.5, 15)

        return False

    def simulate_natural_mouse_movement(self, element):
        """
        Simulate natural human-like mouse movement to an element.

        Args:
            element: The web element to move to
        """
        try:
            actions = ActionChains(self.driver)

            # Start with some random movements
            for _ in range(3):
                offset_x = random.randint(-10, 10)
                offset_y = random.randint(-5, 5)
                actions.move_by_offset(offset_x, offset_y)
                actions.pause(random.uniform(0.1, 0.3))

            # Move to the general area of the element
            actions.move_to_element_with_offset(
                element, random.randint(-10, 10), random.randint(-5, 5)
            )
            actions.pause(random.uniform(0.2, 0.5))

            # Finally move to the element
            actions.move_to_element(element)
            actions.pause(random.uniform(0.3, 0.7))

            # Execute the movement chain
            actions.perform()

            # Add a natural delay after movement
            time.sleep(random.uniform(0.2, 0.4))

        except Exception as e:
            print(f"Mouse movement simulation error (non-critical): {e}")

    def natural_click(self, element):
        """
        Perform a natural human-like click on an element.

        Args:
            element: The web element to click
        """
        try:
            # First move naturally to the element
            self.simulate_natural_mouse_movement(element)

            # Try JavaScript click first (more reliable with Turnstile)
            self.driver.execute_script(
                """
                function simulateClick(element) {
                    // Get element position
                    const rect = element.getBoundingClientRect();
                    const x = rect.left + rect.width / 2 + (Math.random() * 6 - 3);
                    const y = rect.top + rect.height / 2 + (Math.random() * 6 - 3);
                    
                    // Mouse events sequence
                    const events = [
                        new MouseEvent('mouseover', {bubbles: true, cancelable: true, view: window, clientX: x, clientY: y}),
                        new MouseEvent('mousedown', {bubbles: true, cancelable: true, view: window, clientX: x, clientY: y}),
                        new MouseEvent('mouseup', {bubbles: true, cancelable: true, view: window, clientX: x, clientY: y}),
                        new MouseEvent('click', {bubbles: true, cancelable: true, view: window, clientX: x, clientY: y})
                    ];
                    
                    // Send events with slight delays
                    events.forEach((event, i) => {
                        setTimeout(() => element.dispatchEvent(event), i * 30);
                    });
                }
                simulateClick(arguments[0]);
            """,
                element,
            )

            # Add a small delay
            time.sleep(random.uniform(0.1, 0.3))

            # If JavaScript click doesn't work, try native click as fallback
            if random.random() < 0.3:  # 30% of the time use native click as backup
                element.click()

            # Add a natural pause after clicking
            time.sleep(random.uniform(0.3, 0.7))

        except Exception as e:
            # Fall back to direct click if everything else fails
            print(f"Natural click failed, using direct click: {e}")
            try:
                element.click()
            except:
                self.driver.execute_script("arguments[0].click();", element)

    def handle_captcha(self, max_wait_time=600):
        """
        Handle Turnstile captcha with improved detection of completion.
        If the Turnstile API is available, use it; otherwise, fallback to human solving.

        Args:
            max_wait_time: Maximum time to wait for human to solve captcha

        Returns:
            True if captcha solved, False otherwise
        """
        # First try to find the Turnstile sitekey on the page
        try:
            page_source = self.driver.page_source

            # Check if we can find response fields with sitekey attribute
            sitekey = None
            response_fields = self.driver.find_elements(
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
                self.logger.info(f"Found Turnstile sitekey: {sitekey}")
                print("\n" + "=" * 80)
                print(f"TURNSTILE DETECTED - Using API to solve")
                print(f"Sitekey: {sitekey}")
                print("=" * 80 + "\n")

                # Get the current URL
                current_url = self.driver.current_url

                # Call the API to solve the turnstile
                result = self.turnstile_client.solve(
                    url=current_url, sitekey=sitekey, timeout=max_wait_time
                )

                if result["status"] == "success" and result["token"]:
                    # We got a token, inject it into the page
                    token = result["token"]
                    self.logger.info(f"Injecting token: {token[:10]}...")

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
                    injected = self.driver.execute_script(inject_js)

                    if injected:
                        print("✓ Successfully injected Turnstile token")
                        # Give a brief pause for the page to process the token
                        time.sleep(2)
                        return True
                    else:
                        print(
                            "⚠ Failed to find fields to inject token, falling back to human solving"
                        )
                else:
                    error_msg = result.get("message", "Unknown error")
                    print(f"⚠ API failed to solve Turnstile: {error_msg}")
                    print("Falling back to human solving...")
        except Exception as e:
            self.logger.error(f"Error using Turnstile API: {str(e)}")
            print(f"⚠ Error using Turnstile API: {str(e)}")
            print("Falling back to human solving...")

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
            # First, check if user clicked submit button, such that the fields are cleared
            form_fields = self.get_form_fields()
            if form_fields:
                # check if the name field is empty (indicating the form was reset)
                if "name" in form_fields and not form_fields["name"]:
                    return True
            try:
                # Primary check: submit button enabled
                submit_button = self.driver.find_element(
                    By.CSS_SELECTOR, "button[type='submit']"
                )
                if not submit_button.get_attribute("disabled"):
                    return True

                # Backup check: response field populated
                try:
                    response_fields = self.driver.find_elements(
                        By.CSS_SELECTOR,
                        "input[name='cf-turnstile-response'], input[name='g-recaptcha-response']",
                    )
                    for field in response_fields:
                        if (
                            field.get_attribute("value")
                            and len(field.get_attribute("value")) > 10
                        ):
                            return True
                except:
                    pass

                # Additional check: look for success indicators in the page
                page_text = self.driver.page_source.lower()
                success_indicators = [
                    "captcha passed",
                    "verification complete",
                    "challenge complete",
                ]
                for indicator in success_indicators:
                    if indicator in page_text:
                        return True
            except:
                pass
            return False

        # Use progressive wait strategy
        return self.wait_with_progressive_checks(
            is_captcha_solved,
            initial_check=5,
            max_wait=max_wait_time,
            message="Waiting for human to solve captcha",
        )

    def get_form_fields(self) -> Dict:
        """
        Extract all form fields from the Cloudflare abuse report form.

        Returns:
            Dictionary of form field names as type and values as value ({ email: example@gmail.com })
        """
        form_fields = {}

        try:
            # Find all input fields
            input_fields = self.driver.find_elements(By.CSS_SELECTOR, "input")
            for field in input_fields:
                field_name = field.get_attribute("name")
                field_value = field.get_attribute("value")
                if field_name and field_value:
                    form_fields[field_name] = field_value

            # Find all textarea fields
            textarea_fields = self.driver.find_elements(By.CSS_SELECTOR, "textarea")
            for field in textarea_fields:
                field_name = field.get_attribute("name")
                field_value = field.get_attribute("value")
                if field_name and field_value:
                    form_fields[field_name] = field_value

            return form_fields
        except Exception as e:
            print(f"Error getting form fields: {e}")
            return form_fields

    def fill_form_field(self, selector, value, clear_first=True):
        """
        Fill a form field with natural human-like typing.

        Args:
            selector: CSS or By selector tuple for the field
            value: Text to type
            clear_first: Whether to clear the field first

        Returns:
            True if successful, False otherwise
        """
        try:
            # Wait for field to be present and clickable
            field = WebDriverWait(self.driver, 10).until(
                EC.element_to_be_clickable(selector)
            )

            # Move mouse to field naturally and click
            self.natural_click(field)

            # Clear field if needed
            if clear_first:
                field.clear()
                time.sleep(random.uniform(0.2, 0.4))

            # Type with natural rhythm
            for char in value:
                field.send_keys(char)
                time.sleep(random.uniform(0.05, 0.15))

                # Occasionally pause typing as if thinking
                if random.random() < 0.05:  # 5% chance
                    time.sleep(random.uniform(0.2, 0.6))

            # Small pause after completing field
            time.sleep(random.uniform(0.3, 0.7))
            return True

        except Exception as e:
            print(f"Error filling field {selector}: {e}")
            return False

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
            print(f"\n{'='*60}")
            print(f"Processing report #{result['report_number']} for domain: {domain}")
            print(f"{'='*60}")

            # Make sure we have a driver instance (could be using shared browser)
            if not hasattr(self, "driver") or self.driver is None:
                self.setup_driver()

            # Visit a neutral site first to initialize browser state
            self.driver.get("https://example.org")
            time.sleep(random.uniform(1.0, 2.0))

            # Apply stealth JS again to ensure it's active
            self._apply_stealth_js()

            # Load the form with retry logic
            retry_count = 0
            max_retries = 3

            while retry_count < max_retries:
                try:
                    print(
                        f"Loading Cloudflare abuse form (attempt {retry_count+1}/{max_retries})"
                    )

                    # Navigate with a small random delay
                    time.sleep(random.uniform(0.5, 1.5))
                    self.driver.get(self.cloudflare_url)

                    # Wait for form with improved detection
                    WebDriverWait(self.driver, 15).until(
                        EC.presence_of_element_located((By.TAG_NAME, "form"))
                    )

                    print("Form detected on page")
                    break

                except TimeoutException:
                    retry_count += 1
                    if retry_count >= max_retries:
                        result["error"] = "Could not load form after multiple attempts"
                        return result

                    print("Timeout loading form, retrying...")
                    time.sleep(random.uniform(3.0, 5.0))

            # Apply stealth JS after page load to counter page-specific detection
            self._apply_stealth_js()

            # Add some natural browser behavior - scroll slightly
            self.driver.execute_script(
                f"window.scrollBy(0, {random.randint(50, 150)});"
            )
            time.sleep(random.uniform(1.0, 2.0))

            # Fill form fields with more natural human behavior
            print("Filling form fields with natural timing...")

            # Your name
            if not self.fill_form_field((By.NAME, "name"), report_data["name"]):
                result["error"] = "Failed to fill name field"
                return result

            # Email address
            if not self.fill_form_field((By.NAME, "email"), report_data["email"]):
                result["error"] = "Failed to fill email field"
                return result

            # Confirm email address
            if not self.fill_form_field((By.NAME, "email2"), report_data["email"]):
                result["error"] = "Failed to fill confirm email field"
                return result

            # Title (optional)
            if report_data.get("title"):
                self.fill_form_field((By.NAME, "title"), report_data["title"])

            # Company (optional)
            if report_data.get("company"):
                self.fill_form_field((By.NAME, "company"), report_data["company"])

            # Telephone (optional)
            if report_data.get("telephone"):
                self.fill_form_field((By.NAME, "tele"), report_data["telephone"])

            # Scroll down naturally to see more fields
            self.driver.execute_script(
                f"window.scrollBy(0, {random.randint(150, 250)});"
            )
            time.sleep(random.uniform(0.7, 1.5))

            # Evidence URLs
            formatted_domain = (
                f"https://{domain}"
                if not domain.startswith(("http://", "https://"))
                else domain
            )
            if not self.fill_form_field((By.NAME, "urls"), formatted_domain):
                result["error"] = "Failed to fill URLs field"
                return result

            # Justification/Evidence
            if not self.fill_form_field(
                (By.NAME, "justification"), report_data["justification"]
            ):
                result["error"] = "Failed to fill justification field"
                return result

            # Targeted Brand (optional)
            if report_data.get("targeted_brand"):
                self.fill_form_field(
                    (By.NAME, "original_work"), report_data["targeted_brand"]
                )

            # Comments (optional)
            if report_data.get("comments"):
                self.fill_form_field((By.NAME, "comments"), report_data["comments"])

            # Scroll down to checkboxes
            self.driver.execute_script(
                f"window.scrollBy(0, {random.randint(200, 300)});"
            )
            time.sleep(random.uniform(1.0, 1.5))

            # Handle checkboxes with natural timing
            try:
                # Get all checkboxes that are not readonly
                checkboxes = self.driver.find_elements(
                    By.CSS_SELECTOR, "input[type='checkbox']:not([readonly])"
                )
                print(f"Found {len(checkboxes)} non-readonly checkboxes")

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
                                        self.natural_click(checkbox)
                                        print(f"✓ Contact info checkbox {i+1} checked")

                                except Exception as e:
                                    print(f"Warning: Error checking checkbox text: {e}")

                # DSA certification checkbox (last one) - always check this
                dsa_checkbox = checkboxes[-1]
                if not dsa_checkbox.is_selected():
                    # Scroll to make sure it's visible
                    self.driver.execute_script(
                        "arguments[0].scrollIntoView({block: 'center', behavior: 'smooth'});",
                        dsa_checkbox,
                    )
                    time.sleep(random.uniform(0.7, 1.2))

                    # Natural click
                    self.natural_click(dsa_checkbox)
                    print("✓ DSA certification checkbox checked")

            except Exception as e:
                print(f"Error handling checkboxes: {e}")
                result["error"] = f"Failed at checkbox selection: {str(e)}"
                return result

            # Wait for human to solve the captcha with extended time
            if not self.handle_captcha(max_wait_time=600):
                result["error"] = "Timed out waiting for captcha solution"
                print("⨯ Timed out waiting for captcha to be solved")
                return result

            # Find and click the submit button
            try:
                submit_button = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable(
                        (By.CSS_SELECTOR, "button[type='submit']")
                    )
                )
                print("Submit button is enabled, proceeding with submission...")

                # Natural pause before clicking submit
                time.sleep(random.uniform(0.8, 1.5))

                # Click with natural movement
                self.natural_click(submit_button)
                print("Clicked submit button")

                # Wait for confirmation with improved detection
                def is_submission_successful():
                    try:
                        page_text = self.driver.page_source.lower()
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
                submission_success = self.wait_with_progressive_checks(
                    is_submission_successful,
                    initial_check=1,
                    max_wait=20,
                    message="Waiting for submission confirmation",
                )

                if submission_success:
                    result["success"] = True
                    print(
                        f"✓ Report #{result['report_number']} for {domain} submitted successfully!"
                    )

                    # Save cookies after successful submission
                    if self.cookie_file:
                        self.save_cookies()
                else:
                    result["error"] = "Form submitted but no confirmation detected"
                    print("⨯ Form submitted but couldn't confirm success")

            except Exception as e:
                result["error"] = f"Error during form submission: {str(e)}"
                print(f"⨯ Error during form submission: {e}")

            # Increment report counter
            self.report_counter += 1

            # Add natural delay after submission before next domain
            time.sleep(random.uniform(2.0, 4.0))

            return result

        except Exception as e:
            result["error"] = str(e)
            print(f"⨯ Error submitting report for {domain}: {result['error']}")
            return result

    def close(self):
        """Close the browser when done"""
        try:
            if hasattr(self, "driver") and self.driver:
                self.driver.quit()
                print("Browser closed successfully")
        except Exception as e:
            print(f"Error closing browser: {e}")
