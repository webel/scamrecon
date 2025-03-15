"""
Website screenshot capture functionality.
"""

import json
import os
import time
from typing import Dict, List, Optional

import pandas as pd
import undetected_chromedriver as uc
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By

from scamrecon.utils.console import log, print_header
from scamrecon.utils.helpers import normalize_domain


class ScreenshotCapture:
    """
    Captures screenshots of websites for analysis.
    """

    def __init__(
        self, output_dir: str = "screenshots", timeout: int = 20, headless: bool = True
    ):
        """
        Initialize screenshot capture.

        Args:
            output_dir: Directory to save screenshots
            timeout: Page load timeout in seconds
            headless: Whether to run browser in headless mode
        """
        self.output_dir = output_dir
        self.timeout = timeout
        self.headless = headless

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Setup driver
        self.setup_driver()

    def setup_driver(self):
        """Set up Chrome webdriver"""
        options = uc.ChromeOptions()

        if self.headless:
            options.add_argument("--headless")

        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")

        self.driver = uc.Chrome(options=options)
        self.driver.set_page_load_timeout(self.timeout)

    def capture_screenshot(self, url: str, filename: Optional[str] = None) -> Dict:
        """
        Capture a screenshot of a website.

        Args:
            url: URL or domain to capture
            filename: Optional filename for the screenshot

        Returns:
            Dictionary with screenshot information
        """
        print_header(f"CAPTURING SCREENSHOT: {url}")

        # Normalize the URL
        url = normalize_domain(url)

        # Add protocol if missing
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        # Generate filename based on URL if not provided
        if not filename:
            filename = (
                url.replace("https://", "").replace("http://", "").replace("/", "_")
            )
            if not filename.endswith(".png"):
                filename += ".png"

        result = {
            "url": url,
            "success": False,
            "screenshot_path": None,
            "redirected_url": None,
            "error": None,
        }

        try:
            log(f"Loading {url}...", "info")
            self.driver.get(url)

            # Allow some time for the page to fully render
            time.sleep(3)

            # Save redirected URL
            result["redirected_url"] = self.driver.current_url

            # Save screenshot
            screenshot_path = os.path.join(self.output_dir, filename)
            self.driver.save_screenshot(screenshot_path)

            result["success"] = True
            result["screenshot_path"] = screenshot_path

            log(f"Screenshot saved to {screenshot_path}", "success")
            return result

        except (WebDriverException, TimeoutException) as e:
            # If HTTPS fails, try HTTP
            if url.startswith("https://"):
                http_url = url.replace("https://", "http://")
                log(f"HTTPS failed, trying HTTP: {http_url}", "warning")

                try:
                    self.driver.get(http_url)
                    time.sleep(3)

                    result["redirected_url"] = self.driver.current_url

                    # Save screenshot
                    screenshot_path = os.path.join(self.output_dir, filename)
                    self.driver.save_screenshot(screenshot_path)

                    result["success"] = True
                    result["screenshot_path"] = screenshot_path

                    log(f"Screenshot saved to {screenshot_path}", "success")
                    return result

                except Exception as http_error:
                    result["error"] = (
                        f"Both HTTPS and HTTP failed: {str(e)} | {str(http_error)}"
                    )
                    log(result["error"], "error")
            else:
                result["error"] = str(e)
                log(result["error"], "error")

        except Exception as e:
            result["error"] = str(e)
            log(f"Error capturing screenshot: {result['error']}", "error")

        return result

    def close(self):
        """Close browser when done"""
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass


def batch_capture_screenshots(csv_file: str, output_dir: str = "screenshots", skip_lines: int = 0) -> None:
    """
    Capture screenshots for multiple domains from a CSV file.

    Args:
        csv_file: Path to CSV file with domains
        output_dir: Directory to save screenshots
        skip_lines: Number of lines to skip from the CSV file
    """
    try:
        # Load domains from CSV
        df = pd.read_csv(csv_file, skiprows=skip_lines)
        log(f"Loaded {len(df)} entries from {csv_file} (skipped {skip_lines} lines)", "success")

        # Extract domains
        domains = []
        # Always use the second column (index 1) which should contain domains
        # This handles both with and without headers correctly
        if len(df.columns) >= 2:
            domains = df.iloc[:, 1].tolist()  # Always use the second column for domains
        # Fallback options if second column doesn't exist
        elif "id" in df.columns:
            domains = df["id"].tolist()
        elif "id " in df.columns:
            domains = df["id "].tolist()
        elif "domain" in df.columns:
            domains = df["domain"].tolist()
        elif "domain " in df.columns:
            domains = df["domain "].tolist()
        else:
            domains = df.iloc[:, 0].tolist()  # Last resort: use first column

        # Filter valid domains and strip any trailing spaces
        domains = [d.strip() if isinstance(d, str) else d for d in domains]
        domains = [d for d in domains if isinstance(d, str)]
        log(f"Found {len(domains)} domains to capture", "info")

        # Initialize screenshot capture
        screenshot = ScreenshotCapture(output_dir=output_dir)

        results = []

        try:
            # Process each domain
            for i, domain in enumerate(domains):
                log(f"Processing {i+1}/{len(domains)}: {domain}", "info")

                result = screenshot.capture_screenshot(domain)
                results.append(result)

                # Small delay between requests
                time.sleep(1)

        finally:
            screenshot.close()

        # Create screenshots.json file with all data
        screenshots_json = []

        for result in results:
            if result["success"]:
                screenshots_json.append(result["screenshot_path"])

        with open(os.path.join(output_dir, "screenshots.json"), "w") as f:
            json.dump(screenshots_json, f, indent=2)

        log(f"Successfully captured {len(screenshots_json)} screenshots", "success")
        log(f"Results saved to {output_dir}/screenshots.json", "success")

    except Exception as e:
        log(f"Error processing file: {e}", "error")

