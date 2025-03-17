# ScamRecon (Refactored)

A modular toolkit for investigating potentially malicious and scam websites with improved code quality and architecture.

## Features

- Domain information gathering
- Cloudflare bypass techniques
- Security posture assessment
- Technology stack detection
- Screenshot capture and analysis
- Malware detection
- Infrastructure fingerprinting

## New Architecture

This refactored version provides:

1. **Modular Utilities**
   - Browser management with anti-detection
   - Domain processing and normalization
   - Form filling and manipulation
   - Standardized error handling

2. **Cleaner Component Structure**
   - Separation of concerns
   - Reduced code duplication
   - Improved error handling
   - Better extensibility

3. **Example Integrations**
   - End-to-end workflows
   - Combined components
   - Simplified usage

## Installation

Using `uv` (recommended):

```bash
uv venv
uv pip install -e .
```

Or using pip:

```bash
pip install -e .
```

## Usage Examples

### Basic Domain Investigation

```python
from scamrecon.analyzers.tech_detector_refactored import TechDetector

# Initialize detector
detector = TechDetector(headless=True)

# Detect technologies
result = detector.detect_technologies("example.com")

# Print results
print(f"Technologies detected: {result['technologies']}")
```

### Capturing Screenshots

```python
from scamrecon.analyzers.screenshot_refactored import ScreenshotCapture

# Initialize screenshot capturer
capturer = ScreenshotCapture(output_dir="screenshots")

# Capture screenshot
result = capturer.capture_screenshot("example.com")

print(f"Screenshot saved to: {result['screenshot_path']}")
```

### Submitting Abuse Reports

```python
from scamrecon.reporters.cloudflare_refactored import CloudflareReporter

# Initialize reporter
reporter = CloudflareReporter(
    headless=False,
    timeout=30
)

# Report information
report_data = {
    "name": "Your Name",
    "email": "your.email@example.com",
    "justification": "This is a phishing site targeting users."
}

# Submit report
result = reporter.report_domain("malicious-site.com", report_data)

print(f"Report submitted: {result['success']}")
```

### Integration Example

For a complete workflow, see the integration example:

```bash
python examples/integration_example.py
```

This example demonstrates:
1. Loading domains from a file
2. Capturing screenshots
3. Detecting technologies
4. Analyzing security risks
5. Generating a comprehensive report

## Core Refactored Components

### Browser Utilities

```python
from scamrecon.utils.browser import BrowserManager

browser = BrowserManager(headless=True)
browser.navigate_to("https://example.com")
browser.fill_form_field((By.ID, "username"), "testuser")
browser.save_cookies()
```

### Domain Utilities

```python
from scamrecon.utils.domain_utils import normalize_domain, load_domains_from_file

# Normalize domain
clean_domain = normalize_domain("https://example.com/path?query=123")
# Result: "example.com"

# Load domains from file
domains = load_domains_from_file("domains.csv")
```

### Error Handling

```python
from scamrecon.utils.error_handler import ErrorHandler

error_handler = ErrorHandler("my_component")

# Standard logging
error_handler.log("Operation completed", "success")

# Exception handling
try:
    # Some operation
    result = perform_risky_operation()
except Exception as e:
    error_handler.handle_exception(e, "Error during operation")
    
# Retry mechanism
result = error_handler.retry(
    fetch_data,
    max_retries=3,
    retry_delay=1,
    context="Fetching remote data"
)
```

## Development

1. Clone the repository
2. Create a virtual environment: `uv venv`
3. Install development dependencies: `uv pip install -e ".[dev]"`
4. Run tests: `pytest`

## Architecture Improvements

The refactored codebase follows these principles:

1. **Single Responsibility Principle**
   - Each class has a clear, singular purpose
   - Functionality is separated into cohesive modules

2. **Don't Repeat Yourself (DRY)**
   - Common utilities extracted to shared modules
   - Reduces redundancy and maintenance issues

3. **Consistent Error Handling**
   - Standardized approach for all components
   - Improved logging and debugging

4. **Improved State Management**
   - Better browser state handling
   - Persistent sessions where appropriate

5. **Progressive Enhancement**
   - Core functionality works on its own
   - Additional features build on the core

Review the `REFACTORING.md` document for details on the refactoring approach and implementation.