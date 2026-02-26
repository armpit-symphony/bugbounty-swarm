# 🐞 Bug Bounty Swarm

<p align="center">
  <img src="https://img.shields.io/badge/Bug%20Bounty-Autonomous%20Agents-blue" alt="Bug Bounty Swarm">
  <img src="https://img.shields.io/badge/Python-3.8+-green" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-orange" alt="License">
</p>

> Autonomous agent swarm for bug bounty reconnaissance and vulnerability hunting. Built for security researchers, by autonomous agents.

## 🚀 Features

### Reconnaissance
- **DNS Enumeration** - A records, MX, TXT, WHOIS
- **Subdomain Discovery** - CRT.sh, certificate enumeration
- **Port Scanning** - Service detection
- **Shodan/Censys Integration** - Paid APIs supported

### Web Crawling
- **Deep Crawling** - Recursive page discovery
- **Screenshot Capture** - Visual evidence with Puppeteer
- **Form Discovery** - Input extraction for testing
- **JavaScript Analysis** - Endpoint extraction from JS files

### Vulnerability Scanning
- **XSS Scanner** - Reflected, Stored, DOM-based
- **SQL Injection** - Error-based, Union-based
- **IDOR** - Object reference testing
- **SSRF** - Server-side request forgery
- **Authentication** - Login, password reset, sessions

### Enrichment
- **CVE Lookup** - Free cve.circl.lu
- **VirusTotal** - Paid API integration
- **Technology Detection** - Framework fingerprinting

## 📁 Architecture

```
bugbounty-swarm/
├── agents/
│   ├── recon_agent.py           # Domain & network recon
│   ├── crawl_agent.py           # Web crawling & screenshots
│   ├── enrichment_agent.py      # CVE & VT enrichment
│   └── vuln_scanners/
│       ├── xss_scanner.py       # Cross-Site Scripting
│       ├── sqli_scanner.py      # SQL Injection
│       ├── idor_scanner.py      # Insecure Direct Object Reference
│       ├── ssrf_scanner.py      # Server-Side Request Forgery
│       └── auth_scanner.py      # Authentication issues
├── scripts/
│   ├── api_detector.py          # Auto-detect free/paid APIs
│   └── setup_mcp.sh             # MCP server setup
├── configs/
│   └── swarm.conf               # Configuration
├── swarm_orchestrator.py         # Main recon + crawl runner
└── vuln_scanner_orchestrator.py # Vulnerability scanner runner
```

## 🔧 Quick Start

### Basic Usage

```bash
# Clone the repository
git clone https://github.com/armpit-symphony/bugbounty-swarm.git
cd bugbounty-swarm

# Run full reconnaissance + crawl
python3 swarm_orchestrator.py example.com

# Run vulnerability scanners
python3 vuln_scanner_orchestrator.py https://example.com
```

### API Configuration

The swarm works **free by default**. Set API keys to enable enhanced features:

```bash
# Paid APIs (optional)
export SHODAN_API_KEY=your_key
export CENSYS_API_KEY=your_key
export CENSYS_API_SECRET=your_secret
export VIRUSTOTAL_API_KEY=your_key
export GITHUB_TOKEN=your_token

# Check what's enabled
python3 scripts/api_detector.py
```

| API | Free Alternative | Paid Benefit |
|-----|------------------|--------------|
| Shodan | Native DNS | Full subnet data |
| Censys | CRT.sh | Certificate search |
| VirusTotal | cve.circl.lu | IP/domain reputation |
| GitHub | Public API | Rate limits |

## 🎯 Usage Examples

### Full Bug Bounty Workflow

```bash
# 1. Recon + Crawl
python3 swarm_orchestrator.py target.com

# 2. Vulnerability Scanning
python3 vuln_scanner_orchestrator.py https://target.com

# 3. Check output/
ls -la output/
```

### Individual Agents

```bash
# Just recon
python3 agents/recon_agent.py target.com

# Just crawl
python3 agents/crawl_agent.py target.com

# Just XSS scan
python3 agents/vuln_scanners/xss_scanner.py https://target.com
```

## 📊 Output

Results are saved to `output/`:

| File | Description |
|------|-------------|
| `recon_*.json` | DNS, WHOIS, subdomains |
| `crawl_*.json` | Pages, forms, screenshots |
| `vuln_scan_*.json` | All vulnerabilities found |
| `swarm_report_*.md` | Human-readable summary |
| `*_*.html` | Professional HTML report |

## ✅ Profiles

Run modes are defined in `configs/profiles.yaml` and default to `cautious`.

- `passive`: Recon + crawl only
- `cautious`: Recon + crawl + gated active tests
- `active`: Deeper scans (authorized only)

## 🔐 Scope

Targets must be added to `configs/scope.json` before running.

```
{
  "domains": ["example.com"],
  "ips": [],
  "notes": "Authorized targets only"
}
```

## 🧪 Validation

Run the validation harness on a scan report:

```bash
python3 -m core.harness.validate output/vuln_scan_example_com_YYYYMMDD_HHMMSS.json
```

Package evidence:

```bash
python3 scripts/package_evidence.py --output-dir output
```

## 🧾 Evidence Level

Set evidence verbosity in `configs/budget.yaml`:

```
evidence_level: lite | standard | full
```

## 🎯 Focus Mode

Enable target focus in `configs/focus.yaml` to lock the swarm to a single target:

```
enabled: true
target: "example.com"
days: 56
mode: single | rotate
rotate_targets:
  - example.com
  - example.org
rotate_start: "2026-02-01T00:00:00Z"
```

## 🧭 OpenClaw Schema

Schema definition lives in `configs/openclaw_schema.json`.

## ⏱️ Rate Limits

Configure request budgets in `configs/budget.yaml`:

```
requests:
  max_per_minute: 120
  max_per_run: 1000
```

## 🔁 Focus Rotation

Configure rotation quickly:

```bash
python3 scripts/rotate_focus.py --targets "example.com,example.org" --days 56 --enable
```

## ⏲️ Cron Example

Run every day at 3am UTC:

```
0 3 * * * /usr/bin/python3 /home/sparky/bugbounty-swarm/scripts/run_focus.py >> /home/sparky/bugbounty-swarm/output/cron.log 2>&1
```

## 🧰 Make Targets

```bash
make test
make validate
```

## 🤖 OpenClaw Integration

Emit a structured summary for OpenClaw and package artifacts:

```bash
python3 swarm_orchestrator.py example.com \
  --profile cautious \
  --run-vuln \
  --authorized \
  --openclaw \
  --schema-repair \
  --summary-json output/openclaw_summary.json \
  --artifact-dir output/artifacts
```

For vuln scans:

```bash
python3 vuln_scanner_orchestrator.py https://example.com \
  --authorized \
  --profile cautious \
  --tech "Next.js,React" \
  --openclaw \
  --schema-repair \
  --summary-json output/openclaw_vuln_summary.json \
  --artifact-dir output/artifacts
```

Note: schema validation is strict by default. Use `--schema-repair` to auto-fix.

## 🧾 Schema Report

Each run writes `output/openclaw_schema_report.json` with validation status.

## 🧪 Dry Run

Validate configs and emit empty reports without network requests:

```bash
python3 swarm_orchestrator.py example.com --dry-run
python3 vuln_scanner_orchestrator.py https://example.com --dry-run
```

## 📐 Findings Schema

`configs/findings_schema.json` is copied into each vuln output directory.

## 📊 Dashboard

Build a dashboard across runs:

```bash
python3 scripts/build_dashboard.py
```

The dashboard includes:
- Total report counts and target summary
- Per-target aggregation
- Filtering by type and text search

## 📎 Operator Sheet

See `OPERATOR_SHEET.md` for a one-page runbook.

## 🧩 Self-Install (Agent)

To install this repo as an agent skill on the server:

```bash
bash scripts/install_self.sh
```

## 🔒 Safety & Ethics

> **⚠️ WARNING: For authorized testing only**

- Always obtain **written authorization** before testing any target
- This tool is designed for **legitimate security research**
- Unauthorized access is **illegal** and **unethical**
- The authors assume **no liability** for misuse

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch
3. Submit a PR

---

**Note:** This project follows the methodology from [First-Bounty](https://github.com/BehiSecc/First-Bounty) - the beginner-friendly bug bounty roadmap.
