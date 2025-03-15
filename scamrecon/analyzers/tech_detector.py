"""
Technology stack detection for websites.
"""

import json
import os
import time
from typing import Dict, List

import pandas as pd
import requests
import undetected_chromedriver as uc
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from urllib3.exceptions import InsecureRequestWarning

from scamrecon.utils.console import log, print_header
from scamrecon.utils.helpers import get_headers, normalize_domain

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class TechDetector:
    """
    Detects technologies and frameworks used by websites using browser inspection.
    """

    def __init__(self, headless: bool = True, timeout: int = 20):
        """
        Initialize the technology detector.

        Args:
            headless: Whether to run Chrome in headless mode
            timeout: Page load timeout in seconds
        """
        self.headless = headless
        self.timeout = timeout
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

    def detect_technologies(self, url: str) -> Dict:
        """
        Detect technologies using direct page visit with single driver.

        Args:
            url: URL or domain to analyze

        Returns:
            Dictionary with technology detection results
        """
        print_header(f"TECHNOLOGY DETECTION: {url}")

        # Normalize the domain/URL
        url = normalize_domain(url)

        tech_data = {
            "url": url,
            "success": False,
            "redirected_url": None,
            "headers": {},
            "technologies": {},
            "error": None,
        }

        # Try HTTPS first
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        # First try to get headers (quick check)
        headers_data = get_headers(url, timeout=self.timeout)
        if "error" not in headers_data:
            tech_data["headers"] = headers_data

        # Try to load the page
        try:
            log(f"Loading {url} with Chrome...", "info")
            self.driver.get(url)
            time.sleep(3)  # Wait for page load

            # Save redirected URL
            tech_data["redirected_url"] = self.driver.current_url
            tech_data["success"] = True

            # Extract technologies from page
            tech_data["technologies"] = self.extract_technologies_from_page()

            # Add server info
            tech_data["server_info"] = self.get_server_info_from_headers(
                tech_data.get("headers", {})
            )

            # Log findings
            self.log_tech_findings(tech_data)

            return tech_data

        except (WebDriverException, TimeoutException) as e:
            # If HTTPS fails, try HTTP
            if url.startswith("https://"):
                http_url = url.replace("https://", "http://")
                log(f"HTTPS failed, trying HTTP: {http_url}", "warning")

                try:
                    # Get HTTP headers
                    headers_data = get_headers(http_url, timeout=self.timeout)
                    if "error" not in headers_data:
                        tech_data["headers"] = headers_data

                    # Try HTTP page load
                    self.driver.get(http_url)
                    time.sleep(3)

                    tech_data["redirected_url"] = self.driver.current_url
                    tech_data["success"] = True
                    tech_data["technologies"] = self.extract_technologies_from_page()
                    tech_data["server_info"] = self.get_server_info_from_headers(
                        tech_data.get("headers", {})
                    )

                    # Log findings
                    self.log_tech_findings(tech_data)

                    return tech_data
                except Exception as http_error:
                    # Both HTTPS and HTTP failed
                    tech_data["error"] = (
                        f"Both HTTPS and HTTP failed: {str(e)} | {str(http_error)}"
                    )
                    log(tech_data["error"], "error")
            else:
                tech_data["error"] = str(e)
                log(tech_data["error"], "error")

        return tech_data

    def extract_technologies_from_page(self) -> Dict:
        """
        Extract technology clues from page source and structure.

        Returns:
            Dictionary with detected technologies by category
        """
        technologies = {
            "cms": [],
            "ecommerce": [],
            "js_frameworks": [],
            "analytics": [],
            "cdn": [],
            "security": [],
            "server": [],
            "other": [],
        }

        # Get page source
        source = self.driver.page_source

        # === CMS Detection ===
        if "wp-content" in source or "wp-includes" in source:
            technologies["cms"].append("WordPress")
        if "Drupal" in source or "drupal" in source:
            technologies["cms"].append("Drupal")
        if "Joomla" in source or "joomla" in source:
            technologies["cms"].append("Joomla")
        if "Magento" in source or "magento" in source:
            technologies["ecommerce"].append("Magento")
        if "Shopify" in source or "shopify" in source:
            technologies["ecommerce"].append("Shopify")
        if "WooCommerce" in source or "woocommerce" in source:
            technologies["ecommerce"].append("WooCommerce")

        # === JS Frameworks ===
        if "react" in source or "React" in source:
            technologies["js_frameworks"].append("React")
        if "angular" in source or "Angular" in source or "ng-app" in source:
            technologies["js_frameworks"].append("Angular")
        if "vue" in source or "Vue" in source:
            technologies["js_frameworks"].append("Vue.js")
        if "jquery" in source or "jQuery" in source:
            technologies["js_frameworks"].append("jQuery")

        # === Analytics ===
        if (
            "google-analytics" in source
            or "gtag" in source
            or "GA_TRACKING_ID" in source
        ):
            technologies["analytics"].append("Google Analytics")
        if "facebook" in source and "pixel" in source:
            technologies["analytics"].append("Facebook Pixel")

        # === CDN ===
        if "cloudflare" in source:
            technologies["cdn"].append("Cloudflare")
        if "cloudfront" in source:
            technologies["cdn"].append("CloudFront")
        if "jsdelivr" in source:
            technologies["cdn"].append("jsDelivr")

        # === Security ===
        if "recaptcha" in source or "reCAPTCHA" in source:
            technologies["security"].append("reCAPTCHA")
        if "hcaptcha" in source:
            technologies["security"].append("hCaptcha")
        if "turnstile" in source:
            technologies["security"].append("Cloudflare Turnstile")

        # JavaScript execution to detect global objects
        try:
            # jQuery check
            jquery_version = self.driver.execute_script(
                "return typeof jQuery !== 'undefined' ? jQuery.fn.jquery : false;"
            )
            if jquery_version:
                technologies["js_frameworks"].append(f"jQuery {jquery_version}")

            # React check
            has_react = self.driver.execute_script(
                "return typeof React !== 'undefined' || document.querySelector('[data-reactroot], [data-reactid]') !== null;"
            )
            if has_react and "React" not in technologies["js_frameworks"]:
                technologies["js_frameworks"].append("React")

            # Check for Wordpress
            has_wp = self.driver.execute_script(
                "return typeof wp !== 'undefined' || document.body.className.indexOf('wp-') > -1;"
            )
            if has_wp and "WordPress" not in technologies["cms"]:
                technologies["cms"].append("WordPress")

            # Google Analytics
            has_ga = self.driver.execute_script(
                "return typeof ga !== 'undefined' || typeof gtag !== 'undefined' || typeof __gaTracker !== 'undefined';"
            )
            if has_ga and "Google Analytics" not in technologies["analytics"]:
                technologies["analytics"].append("Google Analytics")

        except Exception as e:
            technologies["other"].append(f"JS execution error: {str(e)}")

        # Clean up empty categories
        return {k: v for k, v in technologies.items() if v}

    def get_server_info_from_headers(self, headers: Dict) -> Dict:
        """
        Extract server info from headers.

        Args:
            headers: HTTP headers dictionary

        Returns:
            Dictionary with server information
        """
        server_info = {}

        if not headers or "headers" not in headers:
            return {}

        headers = headers.get("headers", {})

        # Common server headers
        if "Server" in headers:
            server_info["server"] = headers["Server"]

        if "X-Powered-By" in headers:
            server_info["powered_by"] = headers["X-Powered-By"]

        # Cloudflare headers
        cf_headers = [k for k in headers if k.startswith("CF-") or k.startswith("cf-")]
        if cf_headers:
            server_info["cloudflare"] = True
            for h in cf_headers:
                server_info[h] = headers[h]

        # Security headers
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "Content-Type-Options",
            "X-Frame-Options": "Frame-Options",
            "X-XSS-Protection": "XSS-Protection",
        }

        for header, label in security_headers.items():
            if header in headers:
                server_info[label] = headers[header]

        return server_info

    def log_tech_findings(self, tech_data: Dict) -> None:
        """
        Log the findings from technology detection.

        Args:
            tech_data: Technology detection results
        """
        if tech_data["success"]:
            log("Technology detection successful", "success")

            if tech_data.get("redirected_url"):
                log(f"Redirected to: {tech_data['redirected_url']}")

            # Log technologies by category
            technologies = tech_data.get("technologies", {})
            for category, techs in technologies.items():
                if techs:
                    log(f"\n{category.upper()}:", "info")
                    for tech in techs:
                        log(f"  ✓ {tech}")

            # Log server info
            server_info = tech_data.get("server_info", {})
            if server_info:
                log("\nSERVER INFO:", "info")
                for key, value in server_info.items():
                    log(f"  {key}: {value}")
        else:
            log("Technology detection failed", "error")
            if tech_data.get("error"):
                log(f"Error: {tech_data['error']}", "error")

    def close(self):
        """Close browser when done"""
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass


def process_domains(
    csv_file: str, output_dir: str = "tech_results", timeout: int = 20, skip_lines: int = 0
) -> None:
    """
    Process all domains in CSV file.

    Args:
        csv_file: Path to CSV file with domains
        output_dir: Directory to save results
        timeout: Page load timeout in seconds
        skip_lines: Number of lines to skip from the CSV file
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Load domains
    try:
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
        log(f"Found {len(domains)} domains to analyze", "info")

        # Initialize detector
        detector = TechDetector(headless=True, timeout=timeout)

        try:
            all_results = []

            # Process each domain
            for i, domain in enumerate(domains):
                log(f"Processing domain {i+1}/{len(domains)}: {domain}", "info")

                result = detector.detect_technologies(domain)

                # Save individual result
                clean_domain = (
                    domain.replace("https://", "")
                    .replace("http://", "")
                    .replace("/", "_")
                )
                with open(f"{output_dir}/{clean_domain}.json", "w") as f:
                    json.dump(result, f, indent=4)

                all_results.append(result)

                # Create summary every 5 domains or at the end
                if (i + 1) % 5 == 0 or i == len(domains) - 1:
                    create_summary(all_results, output_dir)
                    log(f"Processed {i+1}/{len(domains)} domains", "info")

                # Small delay between requests
                time.sleep(1)

            log("\nAnalysis completed.", "success")
            log(f"Results saved to {output_dir}/", "success")

        finally:
            detector.close()

    except Exception as e:
        log(f"Error processing file: {e}", "error")


def create_summary(results: List[Dict], output_dir: str) -> None:
    """
    Create summary CSV of all results.

    Args:
        results: List of technology detection results
        output_dir: Directory to save summary
    """
    rows = []

    for r in results:
        row = {
            "domain": r.get("url", ""),
            "success": r.get("success", False),
            "redirected_url": r.get("redirected_url", ""),
            "error": r.get("error", ""),
        }

        # Add server info
        server_info = r.get("server_info", {})
        for key, value in server_info.items():
            row[f"server_{key}"] = value

        # Add detected technologies
        tech = r.get("technologies", {})
        for category, items in tech.items():
            if items:
                row[f"tech_{category}"] = ", ".join(items)

        rows.append(row)

    # Create DataFrame and save
    df = pd.DataFrame(rows)
    df.to_csv(f"{output_dir}/summary.csv", index=False)
