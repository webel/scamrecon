"""
Command-line interface for ScamRecon.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import click
from rich.console import Console

from scamrecon.analyzers.screenshot import ScreenshotCapture, batch_capture_screenshots
from scamrecon.analyzers.tech_detector import TechDetector, process_domains
from scamrecon.core.domain_investigator import (
    DomainInvestigator,
    batch_investigate_domains,
)

# Import the improved CloudflareReporter instead of the old batch_submit_reports
from scamrecon.reporters.cloudflare import CloudflareReporter
from scamrecon.utils.config import Config
from scamrecon.utils.console import log, print_header
from scamrecon.utils.helpers import normalize_domain

console = Console()


@click.group()
def cli():
    """ScamRecon - Tools for investigating potentially malicious websites."""
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

    # Run investigation
    investigator = DomainInvestigator(domain_name, config, output_file=output)
    results = investigator.run_investigation()

    click.echo(f"Investigation completed. Results saved to {output}")


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

    # Run detection
    detector = TechDetector(headless=headless, timeout=timeout)

    try:
        result = detector.detect_technologies(domain_name)

        # Save results
        import json

        with open(output, "w") as f:
            json.dump(result, f, indent=2)

        click.echo(f"Technology detection completed. Results saved to {output}")

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
def capture_screenshot(
    domain_name: str,
    output: str = "screenshots",
    timeout: int = 20,
    headless: bool = True,
):
    """Capture a screenshot of a website."""
    # Clean up domain name
    domain_name = normalize_domain(domain_name)

    # Run capture
    capturer = ScreenshotCapture(output_dir=output, timeout=timeout, headless=headless)

    try:
        result = capturer.capture_screenshot(domain_name)

        if result["success"]:
            click.echo(f"Screenshot captured and saved to {result['screenshot_path']}")
        else:
            click.echo(f"Failed to capture screenshot: {result['error']}")

    finally:
        capturer.close()


@cli.group()
def batch():
    """Commands for batch processing domains."""
    pass


@batch.command("process")
@click.argument("csv_file", type=click.Path(exists=True))
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
    "--skip", help="Number of lines to skip from the CSV file", default=0, type=int
)
def batch_process(
    csv_file: str,
    output: str = "results",
    mode: str = "tech",
    timeout: int = 20,
    skip: int = 0,
):
    """Process multiple domains from a CSV file."""
    if not os.path.exists(csv_file):
        click.echo(f"Error: CSV file not found: {csv_file}")
        return

    # Create output directory
    os.makedirs(output, exist_ok=True)

    if mode == "tech":
        print_header("BATCH TECHNOLOGY DETECTION")
        process_domains(csv_file, output_dir=output, timeout=timeout, skip_lines=skip)

    elif mode == "screenshot":
        print_header("BATCH SCREENSHOT CAPTURE")
        batch_capture_screenshots(csv_file, output_dir=output, skip_lines=skip)

    elif mode == "investigate":
        print_header("BATCH DOMAIN INVESTIGATION")
        batch_investigate_domains(
            csv_file, output_dir=output, timeout=timeout, skip_lines=skip
        )


# Modified function to use our improved CloudflareReporter
def batch_submit_reports(
    domains_file: str,
    output_file: str = "report_results.json",
    report_data: Optional[Dict] = None,
    batch_size: int = 50,
    headless: bool = False,
    timeout: int = 20,
    skip_lines: int = 0,
    cookie_file: Optional[str] = None,
) -> None:
    """
    Submit individual reports for each domain using our improved CloudflareReporter.
    """
    try:
        # Local implementation of domain loading to avoid dependency issues
        def load_domains_from_file(domains_file: str) -> List[str]:
            """Load domains from a CSV or TXT file."""
            domains = []
            file_ext = os.path.splitext(domains_file)[1].lower()

            if file_ext == ".csv":
                # Load from CSV
                with open(domains_file, "r") as f:
                    content = f.read()
                    if "," in content.split("\n")[0]:  # Check if it's comma-separated
                        # Split by lines and process each line
                        lines = content.strip().split("\n")
                        for i, line in enumerate(lines):
                            if i == 0:  # Skip header
                                continue
                            parts = line.split(",")
                            if parts and len(parts) > 0:
                                domain = (
                                    parts[1].strip()
                                    if len(parts) > 1
                                    else parts[0].strip()
                                )
                                if domain:
                                    domains.append(domain)
                    else:
                        # If it's not comma-separated, treat as single column
                        lines = content.strip().split("\n")
                        for i, line in enumerate(lines):
                            if i == 0:  # Skip header
                                continue
                            domain = line.strip()
                            if domain:
                                domains.append(domain)
            else:
                # Load from TXT
                with open(domains_file, "r") as f:
                    domains = [line.strip() for line in f if line.strip()]

            return domains

        # Load domains
        domains = load_domains_from_file(domains_file)

        # Skip lines if needed
        if skip_lines > 0:
            domains = domains[skip_lines:]

        console.print(f"[bold]Loaded {len(domains)} domains from {domains_file}[/bold]")
        console.print(
            f"[bold]Each domain will be submitted as a separate report[/bold]"
        )

        # Initialize reporter
        reporter = CloudflareReporter(
            batch_size=batch_size,
            headless=headless,
            timeout=timeout,
            cookie_file=cookie_file,
        )

        all_results = []

        try:
            # Process each domain individually
            for i, domain in enumerate(domains):
                console.print(
                    f"\n[cyan]Processing domain {i+1}/{len(domains)}: {domain}[/cyan]"
                )

                # Submit report for this individual domain
                result = reporter.report_domain(domain, report_data)
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
        console.print(f"[bold red]Error processing domains: {e}[/bold red]")
        raise


@cli.group()
def report():
    """Commands for reporting malicious domains."""
    pass


@report.command("cloudflare")
@click.argument("csv_file", type=click.Path(exists=True))
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
    "--skip", help="Number of lines to skip from the CSV file", default=0, type=int
)
@click.option(
    "--cookie-file",
    help="File to store session cookies for reuse (helps avoid captchas)",
    type=click.Path(),
)
def report_to_cloudflare(
    csv_file: str,
    output: str = "report_results.json",
    report_fields: Optional[str] = None,
    batch_size: int = 50,
    timeout: int = 20,
    headless: bool = False,
    skip: int = 0,
    cookie_file: Optional[str] = None,
):
    """Report phishing domains to Cloudflare's abuse portal. Each domain is submitted as a separate report."""
    print_header("CLOUDFLARE ABUSE REPORTING")

    if not os.path.exists(csv_file):
        click.echo(f"Error: CSV file not found: {csv_file}")
        return

    # Initialize report_data
    report_data = {}

    # Load report fields from JSON file if provided
    if report_fields:
        try:
            with open(report_fields, "r") as f:
                report_data = json.load(f)
            click.echo(f"Loaded report information from {report_fields}")
        except Exception as e:
            click.echo(f"Error loading report fields from {report_fields}: {e}")
            return
    else:
        # Get report information from user
        click.echo("Please provide the following information for your reports:")

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

        # Remove empty fields
        report_data = {k: v for k, v in report_data.items() if v}

    # Output directory for reports
    report_dir = os.path.dirname(output)
    if report_dir and not os.path.exists(report_dir):
        os.makedirs(report_dir, exist_ok=True)

    # Use our improved function that uses CloudflareReporter
    batch_submit_reports(
        domains_file=csv_file,
        output_file=output,
        report_data=report_data,
        batch_size=batch_size,
        headless=headless,
        timeout=timeout,
        skip_lines=skip,
        cookie_file=cookie_file,
    )


# Add a new command for setting up a browser profile
@report.command("setup-profile")
@click.option(
    "--profile-dir",
    default="chrome_profile",
    help="Directory to store browser profile",
)
@click.option(
    "--cookie-file",
    default="reports/cloudflare_cookies.pkl",
    help="Path to save cookies",
)
# TODO: wtf is this AI slop?!
def setup_cloudflare_profile(
    profile_dir: str = "chrome_profile",
    cookie_file: str = "reports/cloudflare_cookies.pkl",
):
    """Set up a persistent browser profile for Cloudflare reporting."""
    print_header("BROWSER PROFILE SETUP")

    # Make sure the output directory exists
    cookie_dir = os.path.dirname(cookie_file)
    if cookie_dir:
        os.makedirs(cookie_dir, exist_ok=True)

    # Try to find the setup_profile script
    possible_paths = [
        "setup_profile.py",  # Current directory
        os.path.join("scamrecon", "reporters", "setup_profile.py"),  # Package path
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "scamrecon",
            "reporters",
            "setup_profile.py",
        ),  # Absolute path
    ]

    setup_script = None
    for path in possible_paths:
        if os.path.exists(path):
            setup_script = path
            break

    if setup_script:
        console.print(f"[green]Running setup script: {setup_script}[/green]")

        # Always run as subprocess since the function doesn't take direct parameters
        import subprocess

        cmd = [
            sys.executable,
            setup_script,
            f"--profile-dir={profile_dir}",
            f"--cookie-file={cookie_file}",
        ]
        console.print(f"[cyan]Command: {' '.join(cmd)}[/cyan]")
        subprocess.run(cmd)
    else:
        console.print("[bold red]Setup profile script not found![/bold red]")
        console.print(
            "Please make sure setup_profile.py is installed in one of these locations:"
        )
        for path in possible_paths:
            console.print(f"- {path}")


@cli.command("version")
def version():
    """Show the version of ScamRecon."""
    click.echo("ScamRecon v0.1.0")


if __name__ == "__main__":
    cli()
