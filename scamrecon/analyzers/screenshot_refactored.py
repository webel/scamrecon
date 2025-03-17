"""
Website screenshot capture functionality using the refactored utilities.
"""

import json
import os
import time
from typing import Dict, List, Optional, Union

# Import our new utilities
from scamrecon.utils.browser import BrowserManager
from scamrecon.utils.domain_utils import normalize_domain, load_domains_from_file
from scamrecon.utils.error_handler import ErrorHandler


class ScreenshotCapture:
    """
    Captures screenshots of websites for analysis with improved reliability.
    Uses the refactored browser utilities for better functionality.
    """

    def __init__(
        self, 
        output_dir: str = "screenshots", 
        timeout: int = 20, 
        headless: bool = True,
        disable_images: bool = False  # New option to disable images for faster loading
    ):
        """
        Initialize screenshot capture.

        Args:
            output_dir: Directory to save screenshots
            timeout: Page load timeout in seconds
            headless: Whether to run browser in headless mode
            disable_images: Whether to disable image loading for faster performance
        """
        self.output_dir = output_dir
        self.timeout = timeout
        self.headless = headless
        self.disable_images = disable_images

        # Initialize error handler
        self.error_handler = ErrorHandler(logger_name="ScreenshotCapture")
        self.log = self.error_handler.log

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Initialize browser manager
        self.browser = BrowserManager(
            headless=headless,
            timeout=timeout,
            disable_images=disable_images
        )

    def capture_screenshot(self, url: str, filename: Optional[str] = None) -> Dict:
        """
        Capture a screenshot of a website with improved error handling.

        Args:
            url: URL or domain to capture
            filename: Optional filename for the screenshot

        Returns:
            Dictionary with screenshot information
        """
        self.log(f"Capturing screenshot for: {url}", "info")

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
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Make sure the browser is initialized
        if not self.browser.driver:
            self.browser.setup_driver()

        # Try HTTPS first with retry mechanism
        try:
            self.log(f"Loading {url}...", "info")
            
            # Use error_handler's retry function to retry on failure
            def load_page():
                self.browser.navigate_to(url, wait_time=3)
                return True
                
            # Try up to 2 times with exponential backoff
            self.error_handler.retry(
                load_page, 
                max_retries=2, 
                retry_delay=1,
                context=f"Loading {url}"
            )

            # Save the redirected URL
            result["redirected_url"] = self.browser.driver.current_url

            # Take screenshot
            screenshot_path = os.path.join(self.output_dir, filename)
            self.browser.driver.save_screenshot(screenshot_path)

            result["success"] = True
            result["screenshot_path"] = screenshot_path

            self.log(f"Screenshot saved to {screenshot_path}", "success")
            return result

        except Exception as https_error:
            # If HTTPS fails, try HTTP
            if url.startswith("https://"):
                http_url = url.replace("https://", "http://")
                self.log(f"HTTPS failed, trying HTTP: {http_url}", "warning")

                try:
                    self.browser.navigate_to(http_url, wait_time=3)
                    
                    # Save the redirected URL
                    result["redirected_url"] = self.browser.driver.current_url

                    # Take screenshot
                    screenshot_path = os.path.join(self.output_dir, filename)
                    self.browser.driver.save_screenshot(screenshot_path)

                    result["success"] = True
                    result["screenshot_path"] = screenshot_path

                    self.log(f"Screenshot saved to {screenshot_path}", "success")
                    return result

                except Exception as http_error:
                    # Both HTTPS and HTTP failed
                    error_message = f"Both HTTPS and HTTP failed: {str(https_error)} | {str(http_error)}"
                    self.log(error_message, "error")
                    result["error"] = error_message
            else:
                # URL was already HTTP and it failed
                self.error_handler.handle_exception(
                    https_error, 
                    context=f"Error capturing screenshot for {url}"
                )
                result["error"] = str(https_error)

        return result

    def capture_fullpage_screenshot(self, url: str, filename: Optional[str] = None) -> Dict:
        """
        Capture a full-page screenshot by scrolling through the page.
        
        Args:
            url: URL or domain to capture
            filename: Optional filename for the screenshot
            
        Returns:
            Dictionary with screenshot information
        """
        # First navigate to the page
        result = self.capture_screenshot(url, filename)
        
        # If the basic screenshot failed, we can't do a full-page screenshot
        if not result["success"]:
            result["error"] = f"Cannot capture full-page screenshot: {result['error']}"
            return result
            
        try:
            # If successful, modify the filename for the full-page version
            if filename:
                fullpage_filename = filename.replace(".png", "_fullpage.png")
            else:
                fullpage_filename = result["screenshot_path"].replace(".png", "_fullpage.png")
                
            # Get the page height
            page_height = self.browser.driver.execute_script(
                "return Math.max(document.body.scrollHeight, document.body.offsetHeight, "
                "document.documentElement.clientHeight, document.documentElement.scrollHeight, "
                "document.documentElement.offsetHeight);"
            )
            
            # Get the window height
            window_height = self.browser.driver.execute_script("return window.innerHeight")
            
            # Calculate number of scrolls needed
            num_scrolls = int(page_height / window_height) + 1
            
            # Scroll and capture each part
            for i in range(num_scrolls):
                # Scroll to position
                self.browser.driver.execute_script(f"window.scrollTo(0, {i * window_height});")
                time.sleep(0.5)  # Wait for any lazy-loaded content
                
                # Capture the current viewport
                part_filename = f"{fullpage_filename.replace('.png', '')}_part{i}.png"
                self.browser.driver.save_screenshot(os.path.join(self.output_dir, part_filename))
                
            self.log(f"Captured full-page screenshot in {num_scrolls} parts", "success")
            
            # Update the result
            result["fullpage_screenshots"] = num_scrolls
            result["fullpage_path"] = os.path.join(self.output_dir, fullpage_filename)
            
            return result
            
        except Exception as e:
            self.error_handler.handle_exception(e, context="Error capturing full-page screenshot")
            result["error"] = f"Error capturing full-page screenshot: {str(e)}"
            return result

    def close(self):
        """Close browser when done"""
        if hasattr(self, "browser"):
            self.browser.close()


def batch_capture_screenshots(
    domains_file: str, 
    output_dir: str = "screenshots", 
    skip_lines: int = 0,
    headless: bool = True,
    timeout: int = 20,
    fullpage: bool = False
) -> Dict:
    """
    Capture screenshots for multiple domains from a file.

    Args:
        domains_file: Path to CSV or TXT file with domains
        output_dir: Directory to save screenshots
        skip_lines: Number of lines to skip from the file
        headless: Whether to run browser in headless mode
        timeout: Page load timeout in seconds
        fullpage: Whether to capture full-page screenshots
        
    Returns:
        Dictionary with batch processing results
    """
    # Initialize error handler
    error_handler = ErrorHandler(logger_name="batch_screenshots")
    log = error_handler.log
    
    # Track statistics
    results = {
        "total_domains": 0,
        "successful_captures": 0,
        "failed_captures": 0,
        "screenshots": [],
        "errors": [],
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": None,
    }
    
    try:
        # Load domains using our unified domain loading utility
        domains = load_domains_from_file(domains_file, skip_lines)
        
        if not domains:
            log(f"No valid domains found in {domains_file}", "error")
            results["error"] = f"No valid domains found in {domains_file}"
            return results
            
        results["total_domains"] = len(domains)
        log(f"Loaded {len(domains)} domains from {domains_file}", "success")

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize screenshot capture
        screenshot = ScreenshotCapture(
            output_dir=output_dir,
            timeout=timeout,
            headless=headless
        )
        
        screenshot_results = []
        
        try:
            # Process each domain
            for i, domain in enumerate(domains):
                log(f"Processing {i+1}/{len(domains)}: {domain}", "info")
                
                # Capture screenshot
                if fullpage:
                    result = screenshot.capture_fullpage_screenshot(domain)
                else:
                    result = screenshot.capture_screenshot(domain)
                    
                screenshot_results.append(result)
                
                # Update statistics
                if result["success"]:
                    results["successful_captures"] += 1
                    results["screenshots"].append({
                        "domain": domain,
                        "path": result["screenshot_path"],
                        "redirected_url": result["redirected_url"]
                    })
                else:
                    results["failed_captures"] += 1
                    results["errors"].append({
                        "domain": domain,
                        "error": result["error"]
                    })
                
                # Small delay between requests
                time.sleep(1)
                
        finally:
            screenshot.close()
        
        # Create screenshots.json file with all data
        with open(os.path.join(output_dir, "screenshots.json"), "w") as f:
            json.dump(screenshot_results, f, indent=2)
            
        # Update final results
        results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        log(f"Successfully captured {results['successful_captures']} screenshots", "success")
        log(f"Failed to capture {results['failed_captures']} screenshots", "warning")
        log(f"Results saved to {output_dir}/screenshots.json", "success")
        
        return results
        
    except Exception as e:
        error_handler.handle_exception(e, "Error in batch screenshot capture")
        results["error"] = str(e)
        results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return results