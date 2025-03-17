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
# Import functions from create_evidence
from scamrecon.reporters.create_evidence import (
    generate_abuse_report,
    generate_cloudflare_report,
    load_investigation_files,
)
# Import campaign analysis and screenshot similarity
from scamrecon.reporters.scam_campaign_analysis import analyze_scam_campaign
from scamrecon.reporters.screenshot_similarity import (
    ScreenshotAnalyzer,
    enhance_reports_with_screenshot_analysis,
    analyze_novelty_patterns,
)
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


# Modified function to use our improved CloudflareReporter with Turnstile API support and evidence
def batch_submit_reports(
    domains_file: str,
    output_file: str = "report_results.json",
    report_data: Optional[Dict] = None,
    batch_size: int = 50,
    headless: bool = False,
    timeout: int = 20,
    skip_lines: int = 0,
    cookie_file: Optional[str] = None,
    turnstile_api_url: str = "http://127.0.0.1:5000",
    use_turnstile_api: bool = True,
    evidence_dir: Optional[str] = None,
    all_investigations: List[Dict] = None,
    use_evidence: bool = False,
) -> None:
    """
    Submit individual reports for each domain using our improved CloudflareReporter.
    
    Args:
        domains_file: File containing domains to report (CSV or TXT)
        output_file: File to save results to
        report_data: Dictionary containing report information
        batch_size: Number of domains to process in a batch
        headless: Whether to run browser in headless mode
        timeout: Page load timeout in seconds
        skip_lines: Number of lines to skip from the input file
        cookie_file: File to store/load session cookies
        turnstile_api_url: URL of the Turnstile Solver API
        use_turnstile_api: Whether to use the Turnstile Solver API
        evidence_dir: Directory containing investigation evidence files
        all_investigations: List of investigation data dictionaries (if already loaded)
        use_evidence: Whether to enhance reports with evidence data
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
        
        # Check if Turnstile API is available
        if use_turnstile_api:
            from scamrecon.reporters.utils.turnstile_client import TurnstileClient
            client = TurnstileClient(api_url=turnstile_api_url)
            if not client.is_api_available():
                console.print(
                    f"[yellow]Warning: Turnstile API at {turnstile_api_url} is not available.[/yellow]"
                )
                console.print(
                    f"[yellow]You can start it with 'scamrecon api'. Falling back to human captcha solving.[/yellow]"
                )
                use_turnstile_api = False
            else:
                console.print(
                    f"[green]Using Turnstile API at {turnstile_api_url} for automated captcha solving[/green]"
                )
                console.print(
                    f"[green]Using shared browser instance for better performance and stability[/green]"
                )

        # Load investigation evidence if not already loaded
        if use_evidence and evidence_dir and not all_investigations:
            console.print(f"[bold]Loading investigation evidence from {evidence_dir}[/bold]")
            all_investigations = load_investigation_files(evidence_dir)
            console.print(f"[green]✓ Loaded {len(all_investigations)} investigation files[/green]")
        
        # Create evidence directory if it doesn't exist yet
        if evidence_dir:
            os.makedirs(os.path.join(evidence_dir, "reports"), exist_ok=True)

        # Initialize reporter with Turnstile API support, shared browser, and evidence directory
        reporter = CloudflareReporter(
            batch_size=batch_size,
            headless=headless,
            timeout=timeout,
            cookie_file=cookie_file,
            turnstile_api_url=turnstile_api_url,
            use_turnstile_api=use_turnstile_api,
            use_shared_browser=True,
            evidence_dir=evidence_dir,
        )

        all_results = []

        try:
            # Process each domain individually
            for i, domain in enumerate(domains):
                console.print(
                    f"\n[cyan]Processing domain {i+1}/{len(domains)}: {domain}[/cyan]"
                )

                # Start with fields from report_fields.json as a base
                domain_report_data = report_data.copy() if report_data else {}
                
                # If evidence is enabled, try to load the cloudflare report file directly
                if use_evidence and evidence_dir:
                    cloudflare_report_path = os.path.join(evidence_dir, f"{domain}_cloudflare_report.json")
                    if os.path.exists(cloudflare_report_path):
                        try:
                            with open(cloudflare_report_path, "r") as f:
                                cloudflare_report = json.load(f)
                                console.print(f"[green]Found direct cloudflare report for {domain}[/green]")
                                
                                # Use the cloudflare report data directly - overriding field values
                                domain_report_data = {**domain_report_data, **cloudflare_report}
                        except Exception as e:
                            console.print(f"[yellow]Error loading cloudflare report: {str(e)}[/yellow]")
                    else:
                        console.print(f"[yellow]No cloudflare report found for {domain} in {evidence_dir}[/yellow]")
                        
                        # No secondary fallback needed

                # Submit report for this individual domain
                result = reporter.report_domain(domain, domain_report_data)
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


@report.command("evidence")
@click.argument("investigation_dir", type=click.Path(exists=True))
@click.option(
    "--output-dir",
    "-o",
    help="Output directory for generated reports",
    default="reports",
    type=click.Path(),
)
def generate_evidence_reports(
    investigation_dir: str,
    output_dir: str = "reports"
):
    """Generate structured abuse reports from investigation data."""
    print_header("EVIDENCE REPORT GENERATION")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Load investigations
    console.print(f"[bold]Loading investigations from {investigation_dir}...[/bold]")
    all_investigations = load_investigation_files(investigation_dir)
    console.print(f"[green]✓ Loaded {len(all_investigations)} domain investigations[/green]")
    
    if not all_investigations:
        console.print("[red]Error: No investigation files found in the specified directory[/red]")
        return
    
    # Check for screenshot analysis data
    screenshot_analysis = None
    screenshot_path = os.path.join(investigation_dir, "..", "screenshot_groups", "screenshot-analysis-report.json")
    if os.path.exists(screenshot_path):
        try:
            with open(screenshot_path, "r") as f:
                screenshot_analysis = json.load(f)
            console.print(f"[green]Found screenshot analysis data with {screenshot_analysis.get('total_groups', 0)} visual similarity groups[/green]")
        except Exception as e:
            console.print(f"[yellow]Error loading screenshot analysis: {str(e)}[/yellow]")
    
    # Generate reports for each domain
    for investigation in all_investigations:
        domain = investigation.get("domain", "unknown")
        console.print(f"\n[cyan]Generating reports for {domain}...[/cyan]")
        
        # Generate Cloudflare report with screenshot analysis if available
        cloudflare_report = generate_cloudflare_report(investigation, all_investigations, screenshot_analysis)
        
        # Save the report
        cloudflare_file = os.path.join(output_dir, f"{domain}_cloudflare_report.json")
        with open(cloudflare_file, "w") as f:
            json.dump(cloudflare_report, f, indent=2)
            
        # Check if this domain is part of a screenshot similarity group
        if screenshot_analysis and cloudflare_report.get("technical_evidence", {}).get("visual_similarity"):
            visual_data = cloudflare_report["technical_evidence"]["visual_similarity"]
            if "screenshot_sim_dir" in visual_data:
                console.print(f"[green]✓ Domain is part of screenshot similarity group {visual_data['group_id']} with evidence in {visual_data['screenshot_sim_dir']}[/green]")
            
        console.print(f"[green]✓ Saved Cloudflare report to {cloudflare_file}[/green]")
    
    console.print(f"\n[bold green]Successfully generated {len(all_investigations)} evidence reports[/bold green]")


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
    csv_file: str,
    output: str = "report_results.json",
    report_fields: Optional[str] = None,
    batch_size: int = 50,
    timeout: int = 20,
    headless: bool = False,
    skip: int = 0,
    cookie_file: Optional[str] = None,
    turnstile_api_url: str = "http://127.0.0.1:5000",
    use_turnstile_api: bool = True,
    evidence_dir: Optional[str] = None,
    use_evidence: bool = False,
):
    """Report phishing domains to Cloudflare's abuse portal. Each domain is submitted as a separate report."""
    print_header("CLOUDFLARE ABUSE REPORTING")

    if not os.path.exists(csv_file):
        click.echo(f"Error: CSV file not found: {csv_file}")
        return

    # Initialize report_data
    report_data = {}

    # Load evidence if specified
    all_investigations = []
    if use_evidence and evidence_dir:
        console.print(f"[bold]Loading investigation evidence from {evidence_dir}[/bold]")
        all_investigations = load_investigation_files(evidence_dir)
        console.print(f"[green]✓ Loaded {len(all_investigations)} investigation files[/green]")
        
        if not all_investigations:
            console.print("[yellow]Warning: No investigation files found. Will use manual report data.[/yellow]")

    # Load report fields from JSON file if provided
    if report_fields:
        try:
            with open(report_fields, "r") as f:
                report_data = json.load(f)
            console.print(f"[green]✓ Loaded report information from {report_fields}[/green]")
        except Exception as e:
            console.print(f"[red]Error loading report fields from {report_fields}: {e}[/red]")
            return
    else:
        # Get report information from user
        console.print("[bold]Please provide the following information for your reports:[/bold]")

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

    # Use our improved function that uses CloudflareReporter with Turnstile API support
    batch_submit_reports(
        domains_file=csv_file,
        output_file=output,
        report_data=report_data,
        batch_size=batch_size,
        headless=headless,
        timeout=timeout,
        skip_lines=skip,
        cookie_file=cookie_file,
        turnstile_api_url=turnstile_api_url,
        use_turnstile_api=use_turnstile_api,
        evidence_dir=evidence_dir,
        all_investigations=all_investigations,
        use_evidence=use_evidence,
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


@report.command("campaign-analysis")
@click.argument("investigation_dir", type=click.Path(exists=True))
@click.option(
    "--screenshots",
    "-s",
    help="Directory containing screenshots",
    required=True,
    type=click.Path(exists=True),
)
@click.option(
    "--output-dir",
    "-o",
    help="Output directory for analysis results",
    default="campaign_analysis",
    type=click.Path(),
)
def analyze_campaign(
    investigation_dir: str,
    screenshots: str,
    output_dir: str = "campaign_analysis"
):
    """Analyze a campaign by combining domain data with screenshot similarity."""
    print_header("SCAM CAMPAIGN ANALYSIS")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Prepare options
    options = {
        "investigation_dir": investigation_dir,
        "screenshot_dir": screenshots,
        "output_dir": output_dir,
        "reporter": {
            "name": "Cookie",
            "email": "slaymeacookie@gmail.com",
            "title": "Security Analyst",
            "company": "HackBack",
        }
    }
    
    # Run analysis
    console.print(f"[bold]Starting campaign analysis...[/bold]")
    console.print(f"[cyan]Loading investigation data from {investigation_dir}[/cyan]")
    console.print(f"[cyan]Loading screenshots from {screenshots}[/cyan]")
    
    results = analyze_scam_campaign(options)
    
    # Print summary
    console.print("\n[bold green]Campaign Analysis Summary:[/bold green]")
    console.print(f"- Domains analyzed: {results['domains_analyzed']}")
    console.print(f"- Infrastructure campaigns identified: {results['infrastructure_campaigns']}")
    console.print(f"- Visual similarity groups: {results['visual_groups']}")
    console.print(f"- Abuse reports generated: {results['reports_generated']}")
    
    console.print(f"\n[green]Results saved to: {output_dir}[/green]")
    console.print(f"[green]Campaign summary: {output_dir}/campaign-summary.json[/green]")
    console.print(f"[green]Enhanced reports: {output_dir}/reports/[/green]")
    console.print(f"[green]Screenshot analysis: {output_dir}/screenshot-analysis/[/green]")


@report.command("screenshot-similarity")
@click.argument("screenshot_dir", type=click.Path(exists=True))
@click.option(
    "--output-dir",
    "-o",
    help="Output directory for analysis results",
    default="similarity_analysis",
    type=click.Path(),
)
@click.option(
    "--investigations",
    "-i",
    help="Directory containing investigation JSON files (optional)",
    type=click.Path(exists=True),
)
def analyze_screenshot_similarity(
    screenshot_dir: str,
    output_dir: str = "similarity_analysis",
    investigations: Optional[str] = None
):
    """Analyze screenshots for visual similarity and group them."""
    print_header("SCREENSHOT SIMILARITY ANALYSIS")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Run analyzer
    console.print(f"[bold]Analyzing screenshots in {screenshot_dir}...[/bold]")
    analyzer = ScreenshotAnalyzer()
    results = analyzer.run(screenshot_dir, output_dir)
    
    if "error" in results:
        console.print(f"[red]Error: {results['error']}[/red]")
        return
    
    # If investigations directory is provided, enhance reports
    if investigations:
        try:
            console.print(f"[cyan]Loading investigation data from {investigations}...[/cyan]")
            investigation_data = load_investigation_files(investigations)
            console.print(f"[green]✓ Loaded {len(investigation_data)} investigation files[/green]")
            
            console.print("[cyan]Enhancing reports with screenshot analysis...[/cyan]")
            enhanced_data = enhance_reports_with_screenshot_analysis(
                screenshot_dir, 
                os.path.join(output_dir, "enhanced"), 
                investigation_data
            )
            
            console.print("[cyan]Generating novelty analysis...[/cyan]")
            novelty = analyze_novelty_patterns(investigation_data, enhanced_data)
            with open(os.path.join(output_dir, "novelty-analysis.json"), "w") as f:
                json.dump(novelty, f, indent=2)
                
            console.print(f"[green]✓ Enhanced analysis saved to {output_dir}/enhanced/[/green]")
            console.print(f"[green]✓ Novelty analysis saved to {output_dir}/novelty-analysis.json[/green]")
        except Exception as e:
            console.print(f"[red]Error enhancing reports with investigation data: {str(e)}[/red]")
    
    # Print summary
    console.print("\n[bold green]Screenshot Analysis Summary:[/bold green]")
    console.print(f"- Screenshots analyzed: {results['total_screenshots']}")
    console.print(f"- Visual similarity groups: {results['total_groups']}")
    console.print(f"\n[green]Results saved to: {output_dir}[/green]")


@cli.command("api")
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", type=int, default=5000, help="Port to listen on")
@click.option("--output-dir", default="turnstile_data", help="Directory to store temporary files")
def run_api(host: str = "127.0.0.1", port: int = 5000, output_dir: str = "turnstile_data"):
    """
    Run the Turnstile Solver API server.
    
    This API provides a standalone service for solving Cloudflare Turnstile challenges.
    Start this server before running the 'report cloudflare' command with '--use-turnstile-api'.
    """
    print_header("TURNSTILE SOLVER API")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Import here to avoid circular imports
    from scamrecon.reporters.utils.turnstile_server import TurnstileSolverAPI
    
    console.print(f"[green]Starting Turnstile Solver API on {host}:{port}[/green]")
    console.print("[cyan]Press Ctrl+C to stop the server[/cyan]")
    
    # Create and run API
    api = TurnstileSolverAPI(host=host, port=port, output_dir=output_dir)
    api.run()


@cli.command("version")
def version():
    """Show the version of ScamRecon."""
    click.echo("ScamRecon v0.1.0")


if __name__ == "__main__":
    cli()
