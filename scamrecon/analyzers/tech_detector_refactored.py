"""
Technology stack detection for websites using refactored utilities.
"""

import json
import os
import time
from typing import Dict, List, Optional, Union, Any

import pandas as pd
import requests
from urllib3.exceptions import InsecureRequestWarning

# Import our new utilities
from scamrecon.utils.browser import BrowserManager
from scamrecon.utils.domain_utils import normalize_domain, load_domains_from_file
from scamrecon.utils.error_handler import ErrorHandler

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class TechDetector:
    """
    Detects technologies and frameworks used by websites using browser inspection.
    Uses the refactored utilities for improved reliability and maintainability.
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
        
        # Initialize error handler for consistent error handling
        self.error_handler = ErrorHandler(logger_name="TechDetector")
        self.log = self.error_handler.log
        
        # Initialize browser manager
        self.browser = BrowserManager(
            headless=headless,
            timeout=timeout
        )

    def get_headers(self, url: str) -> Dict:
        """
        Get HTTP headers from a URL.
        
        Args:
            url: URL to get headers from
            
        Returns:
            Dictionary with header information
        """
        headers_data = {
            "url": url,
            "status_code": None,
            "headers": {},
            "error": None,
        }
        
        try:
            # Use retry for reliability
            def fetch_headers():
                response = requests.head(
                    url, 
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"},
                    timeout=self.timeout,
                    verify=False,  # Disable SSL verification as we're just checking headers
                    allow_redirects=True
                )
                return response
                
            response = self.error_handler.retry(
                fetch_headers, 
                max_retries=2, 
                retry_delay=1,
                context=f"Fetching headers for {url}"
            )
            
            # Save results
            headers_data["status_code"] = response.status_code
            headers_data["headers"] = dict(response.headers)
            headers_data["final_url"] = response.url
            
            return headers_data
            
        except Exception as e:
            self.error_handler.handle_exception(e, f"Error getting headers for {url}")
            headers_data["error"] = str(e)
            return headers_data

    def detect_technologies(self, url: str) -> Dict:
        """
        Detect technologies using direct page visit.

        Args:
            url: URL or domain to analyze

        Returns:
            Dictionary with technology detection results
        """
        self.log(f"Starting technology detection for: {url}", "info")

        # Normalize the domain/URL
        url = normalize_domain(url)

        tech_data = {
            "url": url,
            "success": False,
            "redirected_url": None,
            "headers": {},
            "technologies": {},
            "error": None,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Try HTTPS first
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url

        # First try to get headers (quick check)
        headers_data = self.get_headers(url)
        if "error" not in headers_data:
            tech_data["headers"] = headers_data

        # Make sure the browser is initialized
        if not self.browser.driver:
            self.browser.setup_driver()

        # Try to load the page with retry mechanism
        try:
            self.log(f"Loading {url} with Chrome...", "info")
            
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

            # Save redirected URL
            tech_data["redirected_url"] = self.browser.driver.current_url
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

        except Exception as https_error:
            # If HTTPS fails, try HTTP
            if url.startswith("https://"):
                http_url = url.replace("https://", "http://")
                self.log(f"HTTPS failed, trying HTTP: {http_url}", "warning")

                try:
                    # Get HTTP headers
                    headers_data = self.get_headers(http_url)
                    if "error" not in headers_data:
                        tech_data["headers"] = headers_data

                    # Try HTTP page load
                    self.browser.navigate_to(http_url, wait_time=3)

                    tech_data["redirected_url"] = self.browser.driver.current_url
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
                    error_message = f"Both HTTPS and HTTP failed: {str(https_error)} | {str(http_error)}"
                    self.log(error_message, "error")
                    tech_data["error"] = error_message
            else:
                # URL was already HTTP and it failed
                self.error_handler.handle_exception(
                    https_error, 
                    context=f"Error detecting technologies for {url}"
                )
                tech_data["error"] = str(https_error)

        return tech_data

    def extract_technologies_from_page(self) -> Dict:
        """
        Extract technology clues from page source and structure with enhanced detection.

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
            "hosting": [],
            "other": [],
        }

        # Get page source and normalize
        source = self.browser.driver.page_source.lower()
        
        # Define detection patterns by category
        detection_patterns = {
            "cms": {
                "WordPress": ["wp-content", "wp-includes", "wp-", "/wp-content/"],
                "Drupal": ["drupal", "drupal.settings", "drupal.behaviors"],
                "Joomla": ["joomla", "/templates/", "com_content"],
                "Ghost": ["ghost", "ghost-sdk", "casper"],
                "Contentful": ["contentful", "ctfl"],
                "Strapi": ["strapi", "__strapi"]
            },
            "ecommerce": {
                "Magento": ["magento", "mage", "/skin/frontend/"],
                "Shopify": ["shopify", "myshopify.com", "shopify.com"],
                "WooCommerce": ["woocommerce", "wc-api", "wc_add_to_cart"],
                "PrestaShop": ["prestashop", "presta-shop"],
                "BigCommerce": ["bigcommerce", "bigcommerce.com"],
                "OpenCart": ["opencart", "route=checkout"]
            },
            "js_frameworks": {
                "React": ["react", "reactjs", "react-dom", "_reactrootcontainer"],
                "Angular": ["angular", "ng-app", "ng-controller", "[ng-"],
                "Vue.js": ["vue", "vuejs", "vue-router", "__vue__"],
                "jQuery": ["jquery", "jquery-"],
                "Next.js": ["__next", "next/router"],
                "Gatsby": ["gatsby", "__gatsby"],
                "Svelte": ["svelte", "__svelte"],
                "Nuxt.js": ["nuxt", "__nuxt"]
            },
            "analytics": {
                "Google Analytics": ["google-analytics", "gtag", "ga(", "_ga", "googletagmanager"],
                "Facebook Pixel": ["pixel", "fbevents.js", "fbq("],
                "Matomo/Piwik": ["matomo", "piwik", "_paq"],
                "Hotjar": ["hotjar", "_hjSettings", "_hjIncludedInSample"],
                "Plausible": ["plausible", "plausible.js"],
                "Mixpanel": ["mixpanel"]
            },
            "cdn": {
                "Cloudflare": ["cloudflare", "__cfuid", "cf-", "cloudflare-"],
                "Fastly": ["fastly"],
                "Akamai": ["akamai"],
                "CloudFront": ["cloudfront", "d1", "d2"],
                "jsDelivr": ["jsdelivr"],
                "Unpkg": ["unpkg.com"]
            },
            "security": {
                "reCAPTCHA": ["recaptcha", "grecaptcha"],
                "hCaptcha": ["hcaptcha", "h-captcha"],
                "Cloudflare Turnstile": ["turnstile", "cf-turnstile"],
                "Imperva": ["imperva", "incapsula"],
                "Sucuri": ["sucuri"]
            },
            "hosting": {
                "Netlify": ["netlify", "netlify-"],
                "Vercel": ["vercel", "vercel-", "now.sh"],
                "Firebase": ["firebase", "firebaseapp.com"],
                "GitHub Pages": ["github.io", "githubusercontent"],
                "Heroku": ["herokuapp.com"],
                "AWS": ["amazonaws.com", "aws-"]
            }
        }
        
        # Check for technology signatures in the page source
        for category, tech_patterns in detection_patterns.items():
            for tech_name, patterns in tech_patterns.items():
                for pattern in patterns:
                    if pattern in source:
                        if tech_name not in technologies[category]:
                            technologies[category].append(tech_name)
                            break

        # JavaScript execution to detect global objects and get versions
        try:
            # jQuery check with version
            jquery_version = self.browser.driver.execute_script(
                "return typeof jQuery !== 'undefined' ? jQuery.fn.jquery : false;"
            )
            if jquery_version:
                jquery_entry = f"jQuery {jquery_version}"
                if jquery_entry not in technologies["js_frameworks"] and "jQuery" not in technologies["js_frameworks"]:
                    technologies["js_frameworks"].append(jquery_entry)

            # React check with version
            react_version = self.browser.driver.execute_script(
                """
                try {
                    if (typeof React !== 'undefined') {
                        return React.version || 'detected';
                    } else if (document.querySelector('[data-reactroot], [data-reactid]') !== null) {
                        return 'detected';
                    }
                    return false;
                } catch(e) {
                    return false;
                }
                """
            )
            if react_version and "React" not in technologies["js_frameworks"]:
                react_entry = f"React {react_version}" if react_version != "detected" else "React"
                technologies["js_frameworks"].append(react_entry)

            # WordPress version
            wp_version = self.browser.driver.execute_script(
                """
                try {
                    if (typeof wp !== 'undefined' && wp.version) {
                        return wp.version;
                    }
                    // Try to find meta generator tag with WordPress version
                    const metaGenerator = document.querySelector('meta[name="generator"]');
                    if (metaGenerator && metaGenerator.content && metaGenerator.content.includes('WordPress')) {
                        return metaGenerator.content.match(/WordPress ([0-9.]+)/)[1];
                    }
                    return null;
                } catch(e) {
                    return null;
                }
                """
            )
            if wp_version and "WordPress" in technologies["cms"]:
                # Replace simple "WordPress" with versioned entry
                technologies["cms"].remove("WordPress")
                technologies["cms"].append(f"WordPress {wp_version}")
                
            # Check for Google Tag Manager
            has_gtm = self.browser.driver.execute_script(
                "return typeof google_tag_manager !== 'undefined' || typeof dataLayer !== 'undefined';"
            )
            if has_gtm and "Google Tag Manager" not in technologies["analytics"]:
                technologies["analytics"].append("Google Tag Manager")

        except Exception as e:
            self.error_handler.handle_exception(e, "Error executing JavaScript for technology detection")
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
        cf_headers = [k for k in headers if k.lower().startswith("cf-")]
        if cf_headers:
            server_info["cloudflare"] = True
            for h in cf_headers:
                server_info[h.lower()] = headers[h]

        # Security headers
        security_headers = {
            "Strict-Transport-Security": "hsts",
            "Content-Security-Policy": "csp",
            "X-Content-Type-Options": "content_type_options",
            "X-Frame-Options": "frame_options",
            "X-XSS-Protection": "xss_protection",
            "Permissions-Policy": "permissions_policy",
            "Referrer-Policy": "referrer_policy"
        }

        for header, label in security_headers.items():
            if header in headers:
                server_info[label] = headers[header]
                
        # Check for special server signatures
        if "Server" in headers:
            server = headers["Server"].lower()
            if "nginx" in server:
                server_info["server_type"] = "nginx"
            elif "apache" in server:
                server_info["server_type"] = "apache"
            elif "microsoft" in server or "iis" in server:
                server_info["server_type"] = "iis"
            elif "cloudflare" in server:
                server_info["server_type"] = "cloudflare"
                
        # Extra hosting indicators
        hosting_indicators = {
            "X-Amz-Cf-Id": "aws_cloudfront",
            "X-Vercel-Id": "vercel",
            "X-Netlify": "netlify",
            "X-Powered-By-Pantheon": "pantheon",
            "X-WP-Engine": "wp_engine",
            "X-Kinsta-Cache": "kinsta"
        }
        
        for header, label in hosting_indicators.items():
            if header in headers:
                server_info[label] = True

        return server_info

    def log_tech_findings(self, tech_data: Dict) -> None:
        """
        Log the findings from technology detection.

        Args:
            tech_data: Technology detection results
        """
        if tech_data["success"]:
            self.log("Technology detection successful", "success")

            if tech_data.get("redirected_url"):
                self.log(f"Redirected to: {tech_data['redirected_url']}", "info")

            # Log technologies by category
            technologies = tech_data.get("technologies", {})
            for category, techs in technologies.items():
                if techs:
                    self.log(f"\n{category.upper()}:", "info")
                    for tech in techs:
                        self.log(f"  ✓ {tech}", "debug")

            # Log server info
            server_info = tech_data.get("server_info", {})
            if server_info:
                self.log("\nSERVER INFO:", "info")
                for key, value in server_info.items():
                    self.log(f"  {key}: {value}", "debug")
        else:
            self.log("Technology detection failed", "error")
            if tech_data.get("error"):
                self.log(f"Error: {tech_data['error']}", "error")

    def close(self):
        """Close browser when done"""
        if hasattr(self, "browser"):
            self.browser.close()


def process_domains(
    domains_file: str, 
    output_dir: str = "tech_results", 
    timeout: int = 20, 
    skip_lines: int = 0,
    headless: bool = True
) -> Dict:
    """
    Process all domains in a file.

    Args:
        domains_file: Path to CSV or TXT file with domains
        output_dir: Directory to save results
        timeout: Page load timeout in seconds
        skip_lines: Number of lines to skip from the file
        headless: Whether to run browser in headless mode
        
    Returns:
        Dictionary with processing results
    """
    # Initialize error handler
    error_handler = ErrorHandler(logger_name="process_domains")
    log = error_handler.log
    
    # Track statistics
    results = {
        "total_domains": 0,
        "successful_detections": 0,
        "failed_detections": 0,
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": None,
    }
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Load domains using our unified domain loading utility
        domains = load_domains_from_file(domains_file, skip_lines)
        
        if not domains:
            log(f"No valid domains found in {domains_file}", "error")
            results["error"] = f"No valid domains found in {domains_file}"
            return results
            
        results["total_domains"] = len(domains)
        log(f"Loaded {len(domains)} domains from {domains_file}", "success")

        # Initialize detector
        detector = TechDetector(headless=headless, timeout=timeout)
        
        all_tech_results = []

        try:
            # Process each domain
            for i, domain in enumerate(domains):
                log(f"Processing domain {i+1}/{len(domains)}: {domain}", "info")

                # Detect technologies
                result = detector.detect_technologies(domain)
                all_tech_results.append(result)

                # Update statistics
                if result["success"]:
                    results["successful_detections"] += 1
                else:
                    results["failed_detections"] += 1

                # Save individual result
                clean_domain = (
                    domain.replace("https://", "")
                    .replace("http://", "")
                    .replace("/", "_")
                )
                with open(f"{output_dir}/{clean_domain}.json", "w") as f:
                    json.dump(result, f, indent=4)

                # Create summary every 5 domains or at the end
                if (i + 1) % 5 == 0 or i == len(domains) - 1:
                    create_summary(all_tech_results, output_dir)
                    log(f"Processed {i+1}/{len(domains)} domains", "info")

                # Small delay between requests
                time.sleep(1)

            # Create final summary
            create_summary(all_tech_results, output_dir)
            
            # Update final results
            results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            results["domains_processed"] = len(all_tech_results)
            
            # Save overall results
            with open(f"{output_dir}/processing_results.json", "w") as f:
                json.dump(results, f, indent=4)

            log("\nAnalysis completed.", "success")
            log(f"Results saved to {output_dir}/", "success")
            
            return results

        finally:
            detector.close()

    except Exception as e:
        error_handler.handle_exception(e, "Error processing domains", reraise=False)
        results["error"] = str(e)
        results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        return results


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
    
    # Also save as JSON for easier programmatic use
    with open(f"{output_dir}/summary.json", "w") as f:
        json.dump(rows, f, indent=4)