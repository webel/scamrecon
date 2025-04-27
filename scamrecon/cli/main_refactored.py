"""
Refactored command-line interface for ScamRecon.
This version uses the new utilities and components for improved functionality.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import click
from dotenv import load_dotenv
from rich.console import Console

# Load environment variables from .env file
load_dotenv()

# Import refactored components
from scamrecon.analyzers.screenshot_refactored import (
    ScreenshotCapture,
    batch_capture_screenshots,
)
from scamrecon.analyzers.tech_detector_refactored import TechDetector, process_domains
from scamrecon.core.domain_finder import get_domains_for_ip

# Import the original components that haven't been refactored yet
from scamrecon.core.domain_investigator import (
    DomainInvestigator,
    batch_investigate_domains,
)
from scamrecon.reporters.cloudflare_refactored import (
    CloudflareReporter,
    batch_submit_reports,
)
from scamrecon.reporters.create_evidence import (
    generate_abuse_report,
    generate_cloudflare_report,
    load_investigation_files,
)
from scamrecon.reporters.scam_campaign_analysis import analyze_scam_campaign
from scamrecon.reporters.screenshot_similarity import (
    ScreenshotAnalyzer,
    analyze_novelty_patterns,
    enhance_reports_with_screenshot_analysis,
)

# Import utilities
from scamrecon.utils.config import Config
from scamrecon.utils.domain_utils import load_domains_from_file, normalize_domain
from scamrecon.utils.error_handler import ErrorHandler

# Initialize console and error handler
console = Console()
error_handler = ErrorHandler(logger_name="CLI")
log = error_handler.log


@click.group()
def cli():
    """ScamRecon - Tools for investigating potentially malicious websites.

    This tool provides a comprehensive set of utilities for analyzing potentially
    malicious websites, detecting technologies, capturing screenshots, and submitting
    abuse reports. For detailed help on any command, use the --help option.

    Examples:
      scamrecon domain investigate example.com
      scamrecon tech detect example.com
      scamrecon screenshot capture example.com --fullpage
      scamrecon batch process domains.csv --mode tech
      scamrecon ip find-domains 93.184.216.34
    """
    pass


@cli.group()
def domain():
    """Commands for investigating domains."""
    pass


@domain.command("investigate")
@click.argument("domain_name")
@click.option("--output", "-o", help="Output JSON file path", type=click.Path())
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option(
    "--timeout", "-t", help="Timeout for requests in seconds", default=10, type=int
)
@click.option(
    "--scan-malware", is_flag=True, help="Perform malware scanning", default=True
)
def investigate_domain(
    domain_name: str,
    output: Optional[str] = None,
    verbose: bool = False,
    timeout: int = 10,
    scan_malware: bool = True,
):
    """Investigate a domain for security information and origin server."""
    # Clean up domain name
    domain_name = normalize_domain(domain_name)

    # Setup config
    config = Config.load_default()
    config.timeout = timeout
    config.verbose = verbose
    config.scan_malware = scan_malware

    # Generate output file path if not provided
    if not output:
        os.makedirs("results", exist_ok=True)
        output = f"results/{domain_name}_investigation.json"

    log(f"Starting investigation for {domain_name}", "info")
    start_time = time.time()

    try:
        # Run investigation using existing investigator (not yet refactored)
        investigator = DomainInvestigator(domain_name, config, output_file=output)
        results = investigator.run_investigation()

        duration = time.time() - start_time
        log(f"Investigation completed in {duration:.2f} seconds", "success")
        log(f"Results saved to {output}", "success")
    except Exception as e:
        error_handler.handle_exception(e, "Error during domain investigation")
        click.echo(f"Investigation failed. Error: {str(e)}")
        sys.exit(1)


@cli.group()
def tech():
    """Commands for detecting technologies used by websites."""
    pass


@tech.command("detect")
@click.argument("domain_name")
@click.option("--output", "-o", help="Output JSON file path", type=click.Path())
@click.option(
    "--timeout", "-t", help="Timeout for requests in seconds", default=20, type=int
)
@click.option(
    "--headless/--no-headless", default=True, help="Run browser in headless mode"
)
def detect_tech(
    domain_name: str,
    output: Optional[str] = None,
    timeout: int = 20,
    headless: bool = True,
):
    """Detect technologies used by a website."""
    # Clean up domain name
    domain_name = normalize_domain(domain_name)

    # Generate output file path if not provided
    if not output:
        os.makedirs("results", exist_ok=True)
        output = f"results/{domain_name}_tech.json"

    log(f"Starting technology detection for {domain_name}", "info")
    start_time = time.time()

    # Run detection using refactored detector
    detector = TechDetector(headless=headless, timeout=timeout)

    try:
        result = detector.detect_technologies(domain_name)

        # Save results
        with open(output, "w") as f:
            json.dump(result, f, indent=2)

        duration = time.time() - start_time
        log(f"Technology detection completed in {duration:.2f} seconds", "success")
        log(f"Results saved to {output}", "success")

    except Exception as e:
        error_handler.handle_exception(e, "Error during technology detection")
        click.echo(f"Technology detection failed. Error: {str(e)}")
        sys.exit(1)
    finally:
        detector.close()


@cli.group()
def screenshot():
    """Commands for capturing screenshots of websites."""
    pass


@screenshot.command("capture")
@click.argument("domain_name")
@click.option(
    "--output", "-o", help="Output directory", default="screenshots", type=click.Path()
)
@click.option(
    "--timeout", "-t", help="Timeout for requests in seconds", default=20, type=int
)
@click.option(
    "--headless/--no-headless", default=True, help="Run browser in headless mode"
)
@click.option(
    "--fullpage",
    is_flag=True,
    help="Capture full-page screenshot by scrolling",
    default=False,
)
def capture_screenshot(
    domain_name: str,
    output: str = "screenshots",
    timeout: int = 20,
    headless: bool = True,
    fullpage: bool = False,
):
    """Capture a screenshot of a website."""
    # Clean up domain name
    domain_name = normalize_domain(domain_name)

    log(f"Starting screenshot capture for {domain_name}", "info")
    start_time = time.time()

    # Run capture using refactored component
    capturer = ScreenshotCapture(output_dir=output, timeout=timeout, headless=headless)

    try:
        # Use appropriate method based on fullpage flag
        if fullpage:
            result = capturer.capture_fullpage_screenshot(domain_name)
        else:
            result = capturer.capture_screenshot(domain_name)

        if result["success"]:
            duration = time.time() - start_time
            log(f"Screenshot captured in {duration:.2f} seconds", "success")
            log(f"Screenshot saved to {result['screenshot_path']}", "success")
        else:
            log(f"Failed to capture screenshot: {result['error']}", "error")
            click.echo(f"Screenshot capture failed: {result['error']}")
            sys.exit(1)

    except Exception as e:
        error_handler.handle_exception(e, "Error capturing screenshot")
        click.echo(f"Screenshot capture failed. Error: {str(e)}")
        sys.exit(1)
    finally:
        capturer.close()


@cli.group()
def batch():
    """Commands for batch processing domains."""
    pass


@batch.command("process")
@click.argument("domains_file", type=click.Path(exists=True))
@click.option(
    "--output", "-o", help="Output directory", default="results", type=click.Path()
)
@click.option(
    "--mode",
    "-m",
    help="Processing mode",
    type=click.Choice(["tech", "screenshot", "investigate"]),
    default="tech",
)
@click.option(
    "--timeout", "-t", help="Timeout for requests in seconds", default=20, type=int
)
@click.option(
    "--skip", help="Number of lines to skip from the domains file", default=0, type=int
)
@click.option(
    "--limit", help="Limit number of domains to process", default=None, type=int
)
@click.option(
    "--headless/--no-headless", default=True, help="Run browser in headless mode"
)
def batch_process(
    domains_file: str,
    output: str = "results",
    mode: str = "tech",
    timeout: int = 20,
    skip: int = 0,
    limit: Optional[int] = None,
    headless: bool = True,
):
    """Process multiple domains from a file."""
    # TODO implement limit option for all modes of batch processing
    # Check file exists (redundant with click.Path(exists=True) but good for clarity)
    if not os.path.exists(domains_file):
        click.echo(f"Error: File not found: {domains_file}")
        return

    # Create output directory
    os.makedirs(output, exist_ok=True)

    log(f"Starting batch processing in {mode} mode", "info")
    start_time = time.time()

    try:
        if mode == "tech":
            log("BATCH TECHNOLOGY DETECTION", "info")
            # Use refactored process_domains function
            results = process_domains(
                domains_file,
                output_dir=output,
                timeout=timeout,
                skip_lines=skip,
                headless=headless,
            )
            log(
                f"Successfully processed {results['successful_detections']} domains",
                "success",
            )

        elif mode == "screenshot":
            log("BATCH SCREENSHOT CAPTURE", "info")
            # Use refactored batch_capture_screenshots function
            results = batch_capture_screenshots(
                domains_file,
                output_dir=output,
                skip_lines=skip,
                headless=headless,
                timeout=timeout,
            )
            log(
                f"Successfully captured {results['successful_captures']} screenshots",
                "success",
            )

        elif mode == "investigate":
            log("BATCH DOMAIN INVESTIGATION", "info")
            # Use existing batch_investigate_domains function (not yet refactored)
            batch_investigate_domains(
                domains_file,
                output_dir=output,
                timeout=timeout,
                skip_lines=skip,
                limit=limit,
            )
            log("Batch investigation completed", "success")

        duration = time.time() - start_time
        log(f"Batch processing completed in {duration:.2f} seconds", "success")
        log(f"Results saved to {output}/", "success")

    except Exception as e:
        error_handler.handle_exception(e, f"Error during batch {mode} processing")
        click.echo(f"Batch processing failed. Error: {str(e)}")
        sys.exit(1)


@cli.group()
def report():
    """Commands for reporting malicious domains."""
    pass


@cli.group()
def ip():
    """Commands for IP-related operations."""
    pass


@ip.command("find-domains")
@click.argument("ip_address")
@click.option("--api-key", help="Your Reverse IP API key", envvar="WHOISXML_API_KEY")
@click.option("--output", "-o", help="Output file path for results", type=click.Path())
@click.option(
    "--save-format",
    type=click.Choice(["txt", "json", "csv"]),
    default="txt",
    help="Format to save the results (txt, json, or csv)",
)
def find_domains_by_ip(
    ip_address: str,
    api_key: str,
    output: Optional[str] = None,
    save_format: str = "txt",
):
    """Find all domains that resolve to a specific IP address using the Reverse IP API."""
    if not api_key:
        click.echo(
            "Error: API key is required. Set the WHOISXML_API_KEY environment variable or use --api-key"
        )
        sys.exit(1)

    log(f"Starting domain lookup for IP address: {ip_address}", "info")
    start_time = time.time()

    try:
        # Get the domains using the domain_finder module
        domains = get_domains_for_ip(api_key, ip_address)

        # Display results
        if domains:
            log(f"Found {len(domains)} domains pointing to {ip_address}", "success")
            for domain in domains[:10]:  # Show first 10 domains
                click.echo(domain)
            if len(domains) > 10:
                click.echo(f"... and {len(domains) - 10} more domains")
        else:
            log(f"No domains found for IP address {ip_address}", "info")

        # Save results if output is specified
        if output:
            # Create directory if it doesn't exist
            output_dir = os.path.dirname(output)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

        # Default output name if not provided
        if not output:
            output = f"ip_domains_{ip_address.replace('.', '_')}.{save_format}"

        # Save in the specified format
        if save_format == "txt":
            with open(output, "w") as f:
                for domain in domains:
                    f.write(domain + "\n")
        elif save_format == "json":
            with open(output, "w") as f:
                json.dump({"ip": ip_address, "domains": domains}, f, indent=2)
        elif save_format == "csv":
            with open(output, "w") as f:
                f.write("domain\n")
                for domain in domains:
                    f.write(f"{domain}\n")

        log(f"Results saved to {output}", "success")

        duration = time.time() - start_time
        log(f"Domain lookup completed in {duration:.2f} seconds", "success")

    except Exception as e:
        error_handler.handle_exception(e, "Error during domain lookup")
        click.echo(f"Domain lookup failed. Error: {str(e)}")
        sys.exit(1)


@report.command("cloudflare")
@click.argument("domains_file", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    help="Output JSON file for results",
    default="report_results.json",
    type=click.Path(),
)
@click.option(
    "--report-fields",
    help="JSON file with report field data",
    type=click.Path(exists=True),
)
@click.option(
    "--batch-size",
    type=int,
    default=50,
    help="Number of domains to process (each domain is submitted as a separate report)",
)
@click.option(
    "--timeout", "-t", help="Timeout for page loads in seconds", default=20, type=int
)
@click.option(
    "--headless/--no-headless", default=False, help="Run browser in headless mode"
)
@click.option(
    "--skip", help="Number of lines to skip from the domains file", default=0, type=int
)
@click.option(
    "--cookie-file",
    help="File to store session cookies for reuse (helps avoid captchas)",
    type=click.Path(),
)
@click.option(
    "--profile-dir",
    help="Directory to store browser profile",
    type=click.Path(),
)
@click.option(
    "--turnstile-api-url",
    help="URL of the Turnstile Solver API",
    default="http://127.0.0.1:5000",
)
@click.option(
    "--use-turnstile-api/--no-turnstile-api",
    help="Whether to use the Turnstile Solver API for automated captcha solving",
    default=True,
)
@click.option(
    "--evidence-dir",
    help="Directory containing investigation evidence files",
    type=click.Path(exists=True),
)
@click.option(
    "--use-evidence/--no-evidence",
    help="Whether to use evidence files to enhance report content",
    default=False,
)
def report_to_cloudflare(
    domains_file: str,
    output: str = "report_results.json",
    report_fields: Optional[str] = None,
    batch_size: int = 50,
    timeout: int = 20,
    headless: bool = False,
    skip: int = 0,
    cookie_file: Optional[str] = None,
    profile_dir: Optional[str] = None,
    turnstile_api_url: str = "http://127.0.0.1:5000",
    use_turnstile_api: bool = True,
    evidence_dir: Optional[str] = None,
    use_evidence: bool = False,
):
    """Report phishing domains to Cloudflare's abuse portal using refactored components."""
    log("CLOUDFLARE ABUSE REPORTING", "info")

    # Check if domains file exists
    if not os.path.exists(domains_file):
        click.echo(f"Error: Domains file not found: {domains_file}")
        return

    # Initialize report_data
    report_data = {}

    # Load report fields from JSON file if provided
    if report_fields:
        try:
            with open(report_fields, "r") as f:
                report_data = json.load(f)
            log(f"Loaded report information from {report_fields}", "success")
        except Exception as e:
            error_handler.handle_exception(
                e, f"Error loading report fields from {report_fields}"
            )
            click.echo(
                f"Error loading report fields. Please check file format: {report_fields}"
            )
            return
    else:
        # Get report information from user
        console.print(
            "[bold]Please provide the following information for your reports:[/bold]"
        )

        report_data = {
            "name": click.prompt("Your name"),
            "email": click.prompt("Your email"),
            "title": click.prompt("Your title", default="", show_default=False),
            "company": click.prompt("Company name", default="", show_default=False),
            "telephone": click.prompt("Phone number", default="", show_default=False),
            "justification": click.prompt(
                "Justification/evidence (detailed description of the phishing activity)"
            ),
            "targeted_brand": click.prompt("Targeted brand URL or description"),
            "comments": click.prompt(
                "Additional comments", default="", show_default=False
            ),
            "include_contact_info": click.confirm(
                "Include your contact info with forwarded reports?", default=True
            ),
        }

    # Output directory for reports
    report_dir = os.path.dirname(output)
    if report_dir and not os.path.exists(report_dir):
        os.makedirs(report_dir, exist_ok=True)

    log("Starting abuse report submission process", "info")
    start_time = time.time()

    try:
        # Use refactored batch_submit_reports function
        batch_submit_reports(
            domains_file=domains_file,
            output_file=output,
            report_data=report_data,
            batch_size=batch_size,
            headless=headless,
            timeout=timeout,
            skip_lines=skip,
            cookie_file=cookie_file,
            profile_dir=profile_dir,
            turnstile_api_url=turnstile_api_url,
            use_turnstile_api=use_turnstile_api,
            evidence_dir=evidence_dir,
            use_evidence=use_evidence,
        )

        duration = time.time() - start_time
        log(f"Reporting process completed in {duration:.2f} seconds", "success")
        log(f"Results saved to {output}", "success")
    except Exception as e:
        error_handler.handle_exception(e, "Error during report submission")
        click.echo(f"Report submission failed. Error: {str(e)}")
        sys.exit(1)


@cli.command("version")
def version():
    """Show the version of ScamRecon."""
    click.echo("ScamRecon v0.2.1 (Refactored)")


if __name__ == "__main__":
    cli()
