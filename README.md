# SafeScan CLI — Safe Educational Web Vulnerability Scanner

> **⚠️ DISCLAIMER:** SafeScan is an **educational tool only**. You must **only scan URLs you own or have explicit written permission to test**. Unauthorized scanning of websites you do not own is **illegal** and may violate computer fraud laws (CFAA, Computer Misuse Act, etc.). The authors accept **no liability** for misuse.

## Features

| # | Check | Severity |
|---|-------|----------|
| 1 | **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | Low–Medium |
| 2 | **Reflected XSS Probe** — non-destructive reflection detection on a test parameter | High |
| 3 | **SQL Injection Heuristic** — error-based detection on a test parameter (safe, no exploitation) | High |
| 4 | **Open Directory Listing** — detects common directory index pages | Medium |
| 5 | **Technology Detection** — fingerprints Server, X-Powered-By headers | Low |

## Installation

```bash
git clone https://github.com/ayoublaarichi/SafeScan-CLI.git
cd SafeScan-CLI
python -m pip install -r requirements.txt
```

## Usage

### Basic scan (console output + JSON report)

```bash
python main.py https://your-own-site.com
```

### With a test parameter for XSS / SQLi probes

```bash
python main.py https://your-own-site.com --param "search"
```

### Output formats

```bash
# JSON report only (saved to reports/report.json)
python main.py https://your-own-site.com --json

# HTML report (saved to reports/report.html)
python main.py https://your-own-site.com --html

# Both
python main.py https://your-own-site.com --json --html
```

### Custom output directory

```bash
python main.py https://your-own-site.com --output ./my_reports
```

## Output

- **Console:** colour-coded summary printed to stdout
- **JSON:** structured report at `reports/report.json`
- **HTML:** styled report with severity badges at `reports/report.html`

Each finding includes:
- `check` — module that produced it
- `severity` — `low`, `medium`, or `high`
- `detail` — what was found
- `recommendation` — how to fix it

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
SafeScan-CLI/
├── main.py              # CLI entry-point (argparse)
├── requirements.txt
├── README.md
├── safescan/
│   ├── __init__.py
│   ├── scanner.py       # Orchestrator
│   ├── report.py        # JSON + HTML + console reporters
│   └── modules/
│       ├── __init__.py
│       ├── headers.py
│       ├── xss.py
│       ├── sqli.py
│       ├── directory_listing.py
│       └── tech_detect.py
├── reports/
│   └── .gitkeep
└── tests/
    ├── __init__.py
    └── test_headers.py
```

> Looking for the **web UI version**? See [SafeScan-Web](https://github.com/ayoublaarichi/SafeScan-Web).

## License

MIT — see [LICENSE](LICENSE).
