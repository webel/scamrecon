#!/usr/bin/env python
"""
Integration example demonstrating how to use all the refactored utilities together.
This shows how to effectively chain multiple components for a complete workflow.
"""

import os
import sys
import json
import time
from typing import Dict, List, Optional

# Import refactored utilities
from scamrecon.utils.browser import BrowserManager
from scamrecon.utils.domain_utils import load_domains_from_file, normalize_domain, is_valid_domain
from scamrecon.utils.error_handler import ErrorHandler
from scamrecon.utils.form_utils import fill_form

# Import refactored analyzers
from scamrecon.analyzers.screenshot_refactored import ScreenshotCapture
from scamrecon.analyzers.tech_detector_refactored import TechDetector

# Import refactored reporters
from scamrecon.reporters.cloudflare_refactored import CloudflareReporter


def main():
    """Main function to run the integration example."""
    
    # Initialize error handler
    error_handler = ErrorHandler(logger_name="integration_example")
    log = error_handler.log
    
    # Start timing
    start_time = time.time()
    log("Starting integration example", "info")
    
    # Configuration
    config = {
        "input_file": "examples/example.csv",
        "output_dir": "integration_results",
        "domains_to_process": 3,  # Limit for example purposes
        "headless": True,
        "timeout": 30,
    }
    
    # Create output directories
    os.makedirs(config["output_dir"], exist_ok=True)
    os.makedirs(os.path.join(config["output_dir"], "screenshots"), exist_ok=True)
    os.makedirs(os.path.join(config["output_dir"], "tech_results"), exist_ok=True)
    os.makedirs(os.path.join(config["output_dir"], "reports"), exist_ok=True)
    
    # Load domains
    log(f"Loading domains from {config['input_file']}", "info")
    domains = load_domains_from_file(config["input_file"])
    
    if not domains:
        log("No domains found in input file", "error")
        return
    
    # Limit domains for example
    domains = domains[:config["domains_to_process"]]
    log(f"Processing {len(domains)} domains: {', '.join(domains)}", "info")
    
    # Results collection
    results = {
        "domains": domains,
        "screenshots": [],
        "technologies": [],
        "security_risks": [],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Step 1: Take screenshots
    log("\n=== STEP 1: CAPTURING SCREENSHOTS ===", "info")
    screenshot_capture = ScreenshotCapture(
        output_dir=os.path.join(config["output_dir"], "screenshots"),
        timeout=config["timeout"],
        headless=config["headless"]
    )
    
    try:
        for domain in domains:
            log(f"Capturing screenshot for {domain}", "info")
            screenshot_result = screenshot_capture.capture_screenshot(domain)
            results["screenshots"].append(screenshot_result)
    finally:
        screenshot_capture.close()
    
    # Step 2: Detect technologies
    log("\n=== STEP 2: DETECTING TECHNOLOGIES ===", "info")
    tech_detector = TechDetector(
        headless=config["headless"],
        timeout=config["timeout"]
    )
    
    try:
        for domain in domains:
            log(f"Detecting technologies for {domain}", "info")
            tech_result = tech_detector.detect_technologies(domain)
            results["technologies"].append(tech_result)
            
            # Extract security risks
            if tech_result["success"]:
                server_info = tech_result.get("server_info", {})
                tech_stack = tech_result.get("technologies", {})
                
                # Check for concerning technologies or outdated versions
                security_concerns = []
                
                # Missing security headers
                if "hsts" not in server_info:
                    security_concerns.append("Missing HSTS header")
                if "content_type_options" not in server_info:
                    security_concerns.append("Missing X-Content-Type-Options header")
                if "frame_options" not in server_info:
                    security_concerns.append("Missing X-Frame-Options header")
                    
                # Check for known vulnerable tech versions (simplified example)
                for category, techs in tech_stack.items():
                    for tech in techs:
                        if "WordPress" in tech and "WordPress 4." in tech:
                            security_concerns.append(f"Outdated {tech}")
                        if "jQuery 1." in tech:
                            security_concerns.append(f"Outdated {tech}")
                
                if security_concerns:
                    results["security_risks"].append({
                        "domain": domain,
                        "concerns": security_concerns
                    })
    finally:
        tech_detector.close()
    
    # Step 3: Generate consolidated report
    log("\n=== STEP 3: GENERATING CONSOLIDATED REPORT ===", "info")
    
    # Save full results
    report_path = os.path.join(config["output_dir"], "integrated_results.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
        
    # Create summary
    summary = []
    for domain in domains:
        # Find results for this domain
        domain_screenshots = [s for s in results["screenshots"] if s["url"] == domain or normalize_domain(s["url"]) == domain]
        domain_tech = [t for t in results["technologies"] if t["url"] == domain or normalize_domain(t["url"]) == domain]
        domain_risks = [r for r in results["security_risks"] if r["domain"] == domain]
        
        screenshot_status = "Success" if domain_screenshots and domain_screenshots[0]["success"] else "Failed"
        tech_status = "Success" if domain_tech and domain_tech[0]["success"] else "Failed"
        
        # Extract tech stack
        tech_stack = []
        if domain_tech and domain_tech[0]["success"]:
            for category, techs in domain_tech[0].get("technologies", {}).items():
                tech_stack.extend(techs)
        
        # Format security risks
        security_issues = []
        if domain_risks:
            security_issues = domain_risks[0].get("concerns", [])
        
        # Add to summary
        summary.append({
            "domain": domain,
            "screenshot": screenshot_status,
            "technology_detection": tech_status,
            "tech_stack": tech_stack,
            "security_issues": security_issues,
            "risk_level": "High" if security_issues else "Low"
        })
    
    # Save summary
    summary_path = os.path.join(config["output_dir"], "summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    # End timing
    end_time = time.time()
    duration = end_time - start_time
    log(f"\nIntegration example completed in {duration:.2f} seconds", "success")
    log(f"Full results saved to {report_path}", "success")
    log(f"Summary saved to {summary_path}", "success")


if __name__ == "__main__":
    main()