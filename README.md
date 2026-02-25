# 🐞 Bug Bounty Swarm

Autonomous agent swarm for bug bounty reconnaissance and vulnerability hunting.

## Features

- **Recon Agent** - Domain enumeration, DNS, WHOIS, Shodan/Censys
- **Crawl Agent** - Web crawling, screenshots, form discovery
- **Enrichment Agent** - CVE lookup, VirusTotal, technology detection
- **Orchestrator** - Coordinates all agents into unified workflow

## Architecture

```
┌─────────────────────────────────────────┐
│         SWARM ORCHESTRATOR              │
├─────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐           │
│  │  RECON   │  │  CRAWL   │           │
│  │  AGENT   │  │  AGENT   │           │
│  └──────────┘  └──────────┘           │
│  ┌──────────────────────────┐         │
│  │    ENRICHMENT AGENT       │         │
│  └──────────────────────────┘         │
└─────────────────────────────────────────┘
```

## Quick Start

```bash
# Run full swarm on target
python3 swarm_orchestrator.py example.com
```

## API Configuration

### Free Tier (Default)
- CRT.sh for subdomain enumeration
- cve.circl.lu for CVE lookups
- Puppeteer for screenshots

### Paid APIs (Optional)
Set environment variables to enable:

```bash
export SHODAN_API_KEY=your_key      # Shodan MCP
export CENSYS_API_KEY=your_key       # Censys MCP  
export VIRUSTOTAL_API_KEY=your_key   # VirusTotal enrichment
export GITHUB_TOKEN=your_token       # GitHub code search
```

### Check API Status
```bash
python3 scripts/api_detector.py
```

## Agents

### Recon Agent
- DNS resolution
- WHOIS lookup
- Subdomain enumeration (CRT.sh, Shodan, Censys)
- SSL certificate enumeration

### Crawl Agent
- Web crawling
- Screenshot capture
- Form discovery
- JavaScript endpoint extraction

### Enrichment Agent
- CVE lookup (cve.circl.lu)
- VirusTotal lookups
- Technology detection

## Output

Results saved to `output/`:
- `recon_*.json` - Reconnaissance data
- `crawl_*.json` - Crawl results
- `enrichment_*.json` - Enrichment data
- `swarm_report_*.json` - Full report
- `swarm_report_*.md` - Markdown summary

## Requirements

- Python 3.8+
- Node.js 18+
- puppeteer (`npm install -g puppeteer`)

## Disclaimer

For authorized testing only. Always obtain proper authorization before testing any target.
