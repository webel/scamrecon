# ScamRecon Usage Guide

This document provides examples of common ScamRecon commands and workflows.

## Installation

```bash
# Install from the repository
pip install -e .

# Verify installation
scamrecon version
```

## Basic Commands

### Investigating Domains

```bash
# Basic domain investigation
scamrecon domain investigate example.com

# Save results to a specific file
scamrecon domain investigate example.com --output results/example.json

# Set a longer timeout for slow websites
scamrecon domain investigate example.com --timeout 30
```

### Technology Detection

```bash
# Detect technologies on a website
scamrecon tech detect example.com

# Use a non-headless browser (visible)
scamrecon tech detect example.com --no-headless

# Save results to a specific file
scamrecon tech detect example.com --output results/example_tech.json
```

### Capturing Screenshots

```bash
# Capture a screenshot
scamrecon screenshot capture example.com

# Capture a full-page screenshot by scrolling
scamrecon screenshot capture example.com --fullpage

# Specify the output directory
scamrecon screenshot capture example.com --output my_screenshots
```

### Batch Processing

```bash
# Create a CSV file with domains (id,domain format)
echo "id,domain" > domains.csv
echo "1,example.com" >> domains.csv
echo "2,github.com" >> domains.csv

# Process domains for technology detection
scamrecon batch process domains.csv --mode tech

# Capture screenshots for all domains
scamrecon batch process domains.csv --mode screenshot

# Run full investigations
scamrecon batch process domains.csv --mode investigate

# Specify output directory
scamrecon batch process domains.csv --mode tech --output tech_results
```

### Reporting to Cloudflare

```bash
# First, create a report template
cat > report_fields.json << EOL
{
  "name": "Security Researcher",
  "email": "researcher@example.com",
  "justification": "This website is impersonating a legitimate service and attempting to steal user credentials.",
  "targeted_brand": "Example Corp (example.com)"
}
EOL

# Submit reports
scamrecon report cloudflare domains.csv --report-fields report_fields.json

# Skip the first line if it's a header
scamrecon report cloudflare domains.csv --report-fields report_fields.json --skip 1

# Use the visible browser mode (helpful for debugging)
scamrecon report cloudflare domains.csv --report-fields report_fields.json --no-headless
```

## Advanced Usage

### Using Evidence Files

```bash
# Generate evidence reports from investigation data
scamrecon report evidence investigation_data/ --output-dir evidence/

# Use evidence when reporting to Cloudflare
scamrecon report cloudflare domains.csv --evidence-dir evidence/ --use-evidence
```

### Turnstile API Integration

```bash
# Start the Turnstile Solver API
scamrecon api

# Use the API when reporting
scamrecon report cloudflare domains.csv --report-fields report_fields.json --use-turnstile-api
```

### Working with Browser Profiles

```bash
# Setup a browser profile for Cloudflare reporting
scamrecon report setup-profile --profile-dir chrome_profile --cookie-file cookies.pkl

# Use the profile for reporting
scamrecon report cloudflare domains.csv --report-fields report_fields.json --profile-dir chrome_profile --cookie-file cookies.pkl
```

## Integration Examples

For complete workflow examples, check out the scripts in the `examples/` directory:

- `cli_usage.sh`: Basic CLI usage demonstration
- `analyze_and_report.sh`: Analysis and reporting workflow
- `integration_workflow.sh`: Complete investigation workflow
- `integration_example.py`: Programmatic integration example

## Troubleshooting

If you encounter issues:

1. **Browser-related problems**: Try `--no-headless` to see what's happening
2. **Timeouts**: Increase timeout with `--timeout 60`
3. **Turnstile/Captcha issues**: Make sure the Turnstile API is running (`scamrecon api`)
4. **File not found errors**: Check that all paths exist before running commands