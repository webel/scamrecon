# Remaining Scripts in the examples/ Directory

This directory contains example scripts that demonstrate advanced usage and integration of ScamRecon components. These scripts go beyond the basic command-line interface (CLI) and showcase how to build custom workflows, analyses, and reports.

## analyze_and_report.sh

This shell script orchestrates existing ScamRecon CLI commands into a basic workflow for analyzing domains and preparing reports. It performs the following steps:

1.  Creates output directories for screenshots, tech detection results, and reports.
2.  Creates a sample `domains.csv` file.
3.  Captures screenshots of the domains using the `scamrecon screenshot capture` command.
4.  Detects technologies used by the domains using the `scamrecon tech detect` command.
5.  Batch processes the domains for technology detection using the `scamrecon batch process` command.
6.  Creates a sample `report_template.json` file.
7.  Prints instructions on how to report the domains using the `scamrecon report cloudflare` command.

**Usage:**

```bash
./analyze_and_report.sh
```

## create_cloudflare_domain_list.py

This script generates a list of Cloudflare-protected domains from investigation results. It iterates through `_investigation.json` files in the `results/` directory, checks if the `is_cloudflare_protected` field is `True`, and writes the domain to `cloudflare_urls.txt`. This list can be used as input for the `scamrecon report cloudflare` command.

**Usage:**

```bash
python create_cloudflare_domain_list.py
```

## generate_suspicious_domains_list.py

This script performs advanced analysis to identify and group suspicious domains based on multiple indicators:

1.  Loads data from investigation results, screenshot similarity analysis, and Cloudflare report data.
2.  Groups domains based on visual similarity.
3.  Identifies shared infrastructure (nameservers, CNAME records, IP addresses) among domains.
4.  Groups domains based on name patterns and creation dates.
5.  Scores domains based on suspiciousness.
6.  Combines groups based on multiple indicators.
7.  Generates a summary report in Markdown format, along with lists of high-risk domains and suspicious domain groups.

**Usage:**

```bash
python generate_suspicious_domains_list.py --results <results_dir> --screenshots <screenshot_groups_dir> --evidence <evidence_dir> --output <output_dir>
```

## integration_example.py

This script demonstrates a comprehensive workflow that integrates multiple ScamRecon components:

1.  Loads domains from a file.
2.  Captures screenshots of the domains.
3.  Detects technologies used by the domains.
4.  Identifies potential security risks based on the detected technologies.
5.  Creates a consolidated report with information about screenshots, technologies, and security risks.

**Usage:**

```bash
python integration_example.py
```

## refactored_example.py

This script demonstrates the use of refactored ScamRecon utilities and components, particularly the `CloudflareReporter`. It showcases a streamlined Cloudflare reporting process using the refactored `CloudflareReporter` class and demonstrates integration with a Turnstile API.

**Usage:**

```bash
python refactored_example.py
```

## report_fields.json

This JSON file provides customizable report fields for the Cloudflare reporting process. It allows users to define default values for report fields, which can be used with the `report cloudflare` command or the `CloudflareReporter` class.

**Usage:**

This file is used as input for the `scamrecon report cloudflare` command or the `CloudflareReporter` class in other scripts.

```bash
scamrecon report cloudflare domains.csv --report-fields examples/report_fields.json
```
