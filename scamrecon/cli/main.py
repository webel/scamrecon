"""
Command-line interface for ScamRecon.
"""

import os
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from scamrecon.analyzers.screenshot import ScreenshotCapture, batch_capture_screenshots
from scamrecon.analyzers.tech_detector import TechDetector, process_domains
from scamrecon.core.domain_investigator import DomainInvestigator
from scamrecon.utils.config import Config
from scamrecon.utils.console import log, print_header
from scamrecon.utils.helpers import normalize_domain


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
def batch_process(
    csv_file: str,
    output: str = "results",
    mode: str = "tech",
    timeout: int = 20,
):
    """Process multiple domains from a CSV file."""
    if not os.path.exists(csv_file):
        click.echo(f"Error: CSV file not found: {csv_file}")
        return

    # Create output directory
    os.makedirs(output, exist_ok=True)

    if mode == "tech":
        print_header("BATCH TECHNOLOGY DETECTION")
        process_domains(csv_file, output_dir=output, timeout=timeout)

    elif mode == "screenshot":
        print_header("BATCH SCREENSHOT CAPTURE")
        batch_capture_screenshots(csv_file, output_dir=output)

    elif mode == "investigate":
        print_header("BATCH DOMAIN INVESTIGATION")
        click.echo(
            "Not implemented yet. Use domain investigate command for individual domains."
        )


@cli.command("version")
def version():
    """Show the version of ScamRecon."""
    click.echo("ScamRecon v0.1.0")


if __name__ == "__main__":
    cli()

