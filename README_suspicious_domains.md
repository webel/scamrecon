# Suspicious Domains Analysis Tool

This tool analyzes evidence data from the scamrecon system to identify groups of suspicious domains based on multiple indicators:

1. **Visual similarity** - Domains with similar looking screenshots 
2. **Infrastructure patterns** - Domains sharing nameservers, CNAME records, or IP addresses
3. **Naming patterns** - Domains with similar naming conventions
4. **Creation date proximity** - Domains registered within similar timeframes
5. **High-risk scoring** - Domains with suspicious characteristics (random characters, uncommon TLDs, etc.)

## Usage

```bash
# Activate virtual environment
source .venv/bin/activate

# Run the analysis with default parameters
python examples/generate_suspicious_domains_list.py

# Run with custom parameters
python examples/generate_suspicious_domains_list.py --results ./results --screenshots ./screenshot_groups --evidence ./evidence --output ./custom_output
```

## Output Files

The tool generates several output files in the specified output directory:

- `suspicious_domains_analysis.json` - Complete analysis data in JSON format
- `suspicious_domains_summary.md` - Summary report in Markdown format
- `high_risk_domains.txt` - List of all high-risk domains
- `suspicious_group_N.txt` - Individual files for each suspicious domain group

## How It Works

1. **Data Loading**: Gathers data from investigation results, screenshot analyses, and evidence files
2. **Domain Pattern Analysis**: Analyzes domains for common naming patterns
3. **Infrastructure Analysis**: Groups domains that share infrastructure components
4. **Visual Similarity Grouping**: Uses existing screenshot similarity analysis
5. **Risk Scoring**: Scores domains based on suspicious characteristics
6. **Group Consolidation**: Creates comprehensive suspicious domain groups based on multiple indicators

## Using Results for Reporting

The resulting domain groups can be used in abuse reporting to:

1. Demonstrate campaigns of related suspicious domains
2. Identify infrastructure providers supporting these campaigns
3. Show visual evidence of similar phishing/scam pages
4. Provide strong evidence of coordinated malicious activity

These domain lists can be used with the Cloudflare reporting system or other abuse reporting mechanisms.
