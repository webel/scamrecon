#!/bin/bash
# Example script showing how to analyze domains and submit reports

# Create output directories
mkdir -p analysis_output/screenshots
mkdir -p analysis_output/tech
mkdir -p analysis_output/reports

# First, analyze a list of domains
echo "id,domain" > domains.csv
echo "1,example.com" >> domains.csv
echo "2,github.com" >> domains.csv

# 1. Take screenshots of the domains
echo "=== Taking screenshots ==="
scamrecon screenshot capture example.com --output analysis_output/screenshots
scamrecon screenshot capture github.com --output analysis_output/screenshots

# 2. Detect technologies
echo "=== Detecting technologies ==="
scamrecon tech detect example.com --output analysis_output/tech/example.com.json
scamrecon tech detect github.com --output analysis_output/tech/github.com.json

# 3. Batch process domains for technology detection 
echo "=== Batch processing domains ==="
scamrecon batch process domains.csv --mode tech --output analysis_output/batch

# 4. Create a sample report template 
cat > report_template.json << EOL
{
  "name": "Security Researcher",
  "email": "researcher@example.com",
  "title": "Security Analyst",
  "company": "Security Research Lab",
  "justification": "This website is impersonating a legitimate service and attempting to steal user credentials.",
  "targeted_brand": "Example Corp (example.com)",
  "include_contact_info": true
}
EOL

echo "Report template created: report_template.json"
echo "To report domains, run:"
echo "scamrecon report cloudflare domains.csv --report-fields report_template.json"