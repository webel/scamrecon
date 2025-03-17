#!/bin/bash
# Example workflow demonstrating the complete ScamRecon investigation process

# Setup
echo "=== Setting up investigation ==="
mkdir -p investigation
DOMAIN="example.com"

# 1. Basic investigation
echo "=== Investigating domain: $DOMAIN ==="
scamrecon domain investigate $DOMAIN --output investigation/$DOMAIN.json

# 2. Screenshot capture
echo "=== Capturing screenshots ==="
scamrecon screenshot capture $DOMAIN --output investigation/screenshots

# 3. Technology detection
echo "=== Detecting technologies ==="
scamrecon tech detect $DOMAIN --output investigation/$DOMAIN.tech.json

# 4. Generate a consolidated report
echo "=== Generating consolidated report ==="

# Create a simple Python script to consolidate the results
cat > consolidate.py << EOL
#!/usr/bin/env python
import json
import os
import sys

domain = sys.argv[1]
output_dir = sys.argv[2]

# Load investigation data
with open(f"{output_dir}/{domain}.json") as f:
    investigation = json.load(f)

# Load tech data
with open(f"{output_dir}/{domain}.tech.json") as f:
    tech_data = json.load(f)

# Create consolidated report
report = {
    "domain": domain,
    "timestamp": investigation.get("scan_time", "Unknown"),
    "is_malicious": len(investigation.get("security_issues", [])) > 0,
    "cloudflare_protected": investigation.get("is_cloudflare_protected", False),
    "technologies": tech_data.get("technologies", {}),
    "server_info": tech_data.get("server_info", {}),
    "security_issues": investigation.get("security_issues", []),
    "screenshot": f"{output_dir}/screenshots/{domain}.png"
}

# Save consolidated report
with open(f"{output_dir}/{domain}.report.json", "w") as f:
    json.dump(report, f, indent=2)

print(f"Consolidated report saved to {output_dir}/{domain}.report.json")
EOL

chmod +x consolidate.py

# Run the consolidation script
python consolidate.py $DOMAIN investigation

echo "=== Investigation complete ==="
echo "Results available in the investigation directory:"
ls -la investigation/