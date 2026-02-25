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
