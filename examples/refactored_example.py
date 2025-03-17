#!/usr/bin/env python
"""
Example script demonstrating how to use the refactored utilities.
This shows how to leverage the new modular design for cleaner and more maintainable code.
"""

import os
import json
import time
from typing import Dict, List, Optional

# Import utilities
from scamrecon.utils.browser import BrowserManager
from scamrecon.utils.domain_utils import load_domains_from_file, normalize_domain, is_valid_domain
from scamrecon.utils.error_handler import ErrorHandler
from scamrecon.utils.form_utils import fill_form, extract_form_fields

# Import refactored reporter
from scamrecon.reporters.cloudflare_refactored import CloudflareReporter


def main():
    # Initialize error handler
    error_handler = ErrorHandler(logger_name="example_script")
    log = error_handler.log
    
    # Configuration
    log("Initializing example script", "info")
    config = {
        "domains_file": "examples/example.csv",
        "output_dir": "results",
        "report_fields_file": "examples/report_fields.json",
        "headless": False,  # Set to True for production
        "timeout": 30,
        "cookie_file": "reports/cloudflare_cookies.pkl",
        "profile_dir": "chrome_profile",
        "use_turnstile_api": True,
        "turnstile_api_url": "http://127.0.0.1:5000"
    }
    
    # Create output directory
    os.makedirs(config["output_dir"], exist_ok=True)
    
    # Load domains
    log(f"Loading domains from {config['domains_file']}", "info")
    domains = load_domains_from_file(config["domains_file"])
    log(f"Loaded {len(domains)} domains", "success")
    
    # Load report fields
    try:
        with open(config["report_fields_file"], "r") as f:
            report_data = json.load(f)
        log(f"Loaded report fields from {config['report_fields_file']}", "success")
    except Exception as e:
        error_handler.handle_exception(e, "Failed to load report fields")
        report_data = {
            "name": "Example Name",
            "email": "example@example.com",
            "justification": "This is a phishing site targeting users."
        }
        log("Using default report data", "warning")
    
    # Initialize reporter
    log("Initializing CloudflareReporter", "info")
    reporter = CloudflareReporter(
        output_dir=config["output_dir"],
        timeout=config["timeout"],
        headless=config["headless"],
        cookie_file=config["cookie_file"],
        profile_dir=config["profile_dir"],
        turnstile_api_url=config["turnstile_api_url"],
        use_turnstile_api=config["use_turnstile_api"]
    )
    
    # Process domains
    results = []
    try:
        for i, domain in enumerate(domains):
            log(f"Processing domain {i+1}/{len(domains)}: {domain}", "info")
            
            # Submit report
            result = reporter.report_domain(domain, report_data)
            results.append(result)
            
            # Save interim results
            output_file = os.path.join(config["output_dir"], "report_results.json")
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)
                
            # Brief pause between domains
            time.sleep(2)
    except KeyboardInterrupt:
        log("Process interrupted by user", "warning")
    finally:
        # Close browser
        reporter.close()
    
    # Print summary
    successful = sum(1 for r in results if r.get("success", False))
    log(f"Summary: {successful}/{len(domains)} reports submitted successfully", "info")
    
    
if __name__ == "__main__":
    main()