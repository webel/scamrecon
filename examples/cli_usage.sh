#!/bin/bash
# Example script demonstrating the usage of the refactored ScamRecon CLI

# Make the script stop on errors
set -e

# Display header
echo "========================================="
echo "ScamRecon v2 CLI Usage Examples"
echo "========================================="

# Check version
echo "Checking version..."
scamrecon-v2 version

# Create a directory for test output
mkdir -p cli_test_output

# Simple domain investigation
echo -e "\n\n========================================="
echo "1. Investigating a single domain"
echo "========================================="
scamrecon-v2 domain investigate example.com --output cli_test_output/example_investigation.json

# Technology detection
echo -e "\n\n========================================="
echo "2. Detecting technologies on a domain"
echo "========================================="
scamrecon-v2 tech detect example.com --output cli_test_output/example_tech.json

# Taking a screenshot
echo -e "\n\n========================================="
echo "3. Taking a screenshot of a domain"
echo "========================================="
scamrecon-v2 screenshot capture example.com --output cli_test_output/screenshots

# Create test CSV file for batch processing
echo -e "\n\n========================================="
echo "Creating test domains file for batch processing"
echo "========================================="
echo "id,domain,description" > cli_test_output/test_domains.csv
echo "1,example.com,Example Domain" >> cli_test_output/test_domains.csv
echo "2,github.com,GitHub" >> cli_test_output/test_domains.csv
echo "3,python.org,Python" >> cli_test_output/test_domains.csv

# Batch technology detection
echo -e "\n\n========================================="
echo "4. Batch technology detection"
echo "========================================="
scamrecon-v2 batch process cli_test_output/test_domains.csv --output cli_test_output/batch_tech --mode tech

# View the results
echo -e "\n\n========================================="
echo "Results summary:"
echo "========================================="
echo "CLI test results have been saved to cli_test_output/"
ls -la cli_test_output/

echo -e "\n\nDone! 🎉"