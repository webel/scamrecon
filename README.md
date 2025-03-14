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
```

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

