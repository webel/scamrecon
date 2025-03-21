# ScamRecon

A modular toolkit for investigating potentially malicious and scam websites.

## Features

- Domain information gathering
- Cloudflare bypass techniques
- Security posture assessment
- Technology stack detection
- Screenshot capture and analysis
- Malware detection
- Infrastructure fingerprinting

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

## Usage

```bash
# Investigate a single domain
scamrecon domain investigate example.com

# Detect technologies used by a domain
scamrecon tech detect example.com

# Batch process a list of domains
scamrecon batch process domains.csv --output results/

# Take screenshots of websites
scamrecon screenshot capture example.com

# Take full-page screenshots (new feature)
scamrecon screenshot capture example.com --fullpage
```

### Enhanced Features

The latest version includes improved functionality with:

- Better error handling and reporting
- Consistent performance metrics
- Enhanced screenshot capture with full-page option
- More reliable technology detection
- Improved security analysis

See [USAGE.md](USAGE.md) for comprehensive examples and [REFACTORING.md](REFACTORING.md) for details on the new architecture.

## Configuration

Create a `.env` file in your project root with your API keys:

```
VIRUSTOTAL_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

## Development

1. Clone the repository
2. Create a virtual environment: `uv venv`
3. Install development dependencies: `uv pip install -e ".[dev]"`
4. Run tests: `pytest`

## TODO

Check these IPs

2606:4700::6812:1430
2606:4700::6812:1530
2a03:f480:1:d::cd
46.36.216.64
72.52.4.119
104.18.20.48
