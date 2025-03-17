"""
Browser management utilities for consistent browser instance management.
"""

import os
import pickle
import random
import time
from typing import Dict, List, Optional, Union, Any

import undetected_chromedriver as uc
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from .stealth import apply_stealth_js


class BrowserManager:
    """
    Manager for browser instances with anti-detection and session persistence.
    Provides consistent browser management across different components.
    """

    def __init__(
        self,
        headless: bool = False,
        timeout: int = 30,
        user_agent: Optional[str] = None,
        profile_dir: Optional[str] = None,
        cookie_file: Optional[str] = None,
        disable_images: bool = False,
    ):
        """
        Initialize a browser manager.
        
        Args:
            headless: Whether to run browser in headless mode
            timeout: Page load timeout in seconds
            user_agent: Custom user agent string, or None for default
            profile_dir: Path to Chrome profile directory
            cookie_file: Path to save/load cookies
            disable_images: Whether to disable image loading (faster)
        """
        self.headless = headless
        self.timeout = timeout
        self.profile_dir = profile_dir
        self.cookie_file = cookie_file
        self.disable_images = disable_images
        
        # Set default user agent if not provided
        if not user_agent:
            self.user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        else:
            self.user_agent = user_agent
            
        self.driver = None
        self.wait = None
        
    def setup_driver(self):
        """
        Set up Chrome webdriver with enhanced anti-detection measures.
        
        Returns:
            WebDriver: The configured browser instance
        """
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
        
        # Disable images if requested
        if self.disable_images:
            prefs = {"profile.managed_default_content_settings.images": 2}
            options.add_experimental_option("prefs", prefs)

        # If we have a profile directory, use it
        if self.profile_dir and os.path.exists(self.profile_dir):
            options.add_argument(f"--user-data-dir={self.profile_dir}")
            print(f"Using existing Chrome profile: {self.profile_dir}")

        # Initialize the driver with improved settings
        self.driver = uc.Chrome(options=options, use_subprocess=True)
        self.driver.set_page_load_timeout(self.timeout)
        self.driver.set_script_timeout(self.timeout)

        # Apply basic anti-detection JS after launch
        apply_stealth_js(self.driver)

        # Wait setup with improved timeouts
        self.wait = WebDriverWait(self.driver, 10)

        # Load cookies if a cookie file is provided
        if self.cookie_file and os.path.exists(self.cookie_file):
            self.load_cookies()
            
        return self.driver

    def load_cookies(self) -> bool:
        """
        Load cookies and browser state from file to maintain session.

        Returns:
            bool: True if successful, False otherwise
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
        Save comprehensive browser state after successful session.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.driver or not self.cookie_file:
            return False
            
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

            # Save comprehensive state
            state_data = {
                "cookies": cookies,
                "local_storage": local_storage,
                "session_storage": session_storage,
                "user_agent": self.user_agent,
                "profile_dir": self.profile_dir,
                "last_saved": time.time(),
            }

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(self.cookie_file)), exist_ok=True)
            
            with open(self.cookie_file, "wb") as f:
                pickle.dump(state_data, f)

            print(f"✓ Browser state saved to {self.cookie_file}")
            return True

        except Exception as e:
            print(f"Error saving browser state: {e}")
            return False
            
    def navigate_to(self, url: str, wait_time: Optional[int] = None) -> bool:
        """
        Navigate to a URL with proper error handling and random delays.
        
        Args:
            url: The URL to navigate to
            wait_time: Optional wait time after navigation, or None for random
            
        Returns:
            bool: True if navigation succeeded
        """
        if not self.driver:
            self.setup_driver()
            
        try:
            # Add a small random delay before navigation to appear more human-like
            time.sleep(random.uniform(0.5, 1.5))
            
            # Navigate to the URL
            self.driver.get(url)
            
            # Add a random delay after navigation
            if wait_time is None:
                time.sleep(random.uniform(2.0, 4.0)) 
            else:
                time.sleep(wait_time)
                
            # Apply stealth JS again after navigation
            apply_stealth_js(self.driver)
            
            return True
        except Exception as e:
            print(f"Error navigating to {url}: {e}")
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

            # Try JavaScript click first (more reliable with complex elements)
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

    def fill_form_field(self, selector, value, clear_first=True):
        """
        Fill a form field with natural human-like typing.

        Args:
            selector: CSS or By selector tuple for the field
            value: Text to type
            clear_first: Whether to clear the field first

        Returns:
            bool: True if successful, False otherwise
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
    
    def wait_with_progressive_checks(
        self,
        condition_func,
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
            bool: True if condition was met, False on timeout
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
            
    def close(self):
        """Close the browser instance and clean up."""
        if self.driver:
            try:
                self.driver.quit()
                self.driver = None
                self.wait = None
                print("Browser closed successfully")
            except Exception as e:
                print(f"Error closing browser: {e}")
    
    def __enter__(self):
        """Support for context manager pattern."""
        if not self.driver:
            self.setup_driver()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up resources when exiting context."""
        self.close()