#!/usr/bin/env python3
"""
Bug Bounty Swarm Orchestrator
Coordinates recon, crawl, and enrichment agents
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

# Add agents to path
AGENT_DIR = Path(__file__).parent
sys.path.insert(0, str(AGENT_DIR))

from agents.recon_agent import ReconAgent
from agents.crawl_agent import CrawlAgent
from agents.enrichment_agent import EnrichmentAgent

# Config
OUTPUT_DIR = "/home/sparky/.openclaw/workspace/bugbounty-swarm/output"

class SwarmOrchestrator:
    def __init__(self, target):
        self.target = target
        self.results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "recon": None,
            "crawl": None,
            "enrichment": None,
            "summary": {}
        }
        
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    def run_full_swarm(self):
        """Run complete bug bounty workflow"""
        print("=" * 60)
        print("🐞 BUG BOUNTY SWARM - STARTING")
        print(f"   Target: {self.target}")
        print("=" * 60)
        
        # Phase 1: Recon
        print("\n📡 PHASE 1: RECON")
        print("-" * 40)
        try:
            recon = ReconAgent(self.target)
            self.results["recon"] = recon.run()
        except Exception as e:
            print(f"   ❌ Recon failed: {e}")
        
        # Phase 2: Crawl
        print("\n🕷️ PHASE 2: CRAWL")
        print("-" * 40)
        try:
            crawl = CrawlAgent(self.target, max_pages=15)
            self.results["crawl"] = crawl.run()
        except Exception as e:
            print(f"   ❌ Crawl failed: {e}")
        
        # Phase 3: Enrichment
        print("\n🔍 PHASE 3: ENRICHMENT")
        print("-" * 40)
        try:
            enrichment = EnrichmentAgent()
            
            # Detect technologies
            enrichment.detect_tech(f"https://{self.target}")
            
            # If we found IPs, enrich them
            if self.results.get("recon") and self.results["recon"].get("dns", {}).get("a"):
                for ip in self.results["recon"]["dns"]["a"]:
                    enrichment.lookup_ip_virustotal(ip)
            
            enrichment.save_results()
            self.results["enrichment"] = enrichment.results
        except Exception as e:
            print(f"   ❌ Enrichment failed: {e}")
        
        # Generate summary
        self.generate_summary()
        
        # Save final report
        self.save_report()
        
        print("\n" + "=" * 60)
        print("✅ SWARM COMPLETE")
        print("=" * 60)
        
        return self.results
    
    def generate_summary(self):
        """Generate summary of findings"""
        summary = {
            "subdomains_found": len(self.results.get("recon", {}).get("subdomains", [])),
            "pages_crawled": len(self.results.get("crawl", {}).get("pages", [])),
            "screenshots": len(self.results.get("crawl", {}).get("screenshots", [])),
            "forms_found": len(self.results.get("crawl", {}).get("forms", [])),
            "js_files": len(self.results.get("crawl", {}).get("js_files", [])),
            "tech_detected": []
        }
        
        # Extract tech
        if self.results.get("enrichment", {}).get("tech_detection"):
            for td in self.results["enrichment"]["tech_detection"]:
                summary["tech_detected"].extend(td.get("tech", []))
        
        summary["tech_detected"] = list(set(summary["tech_detected"]))
        
        self.results["summary"] = summary
        
        print("\n📊 SUMMARY:")
        print(f"   Subdomains: {summary['subdomains_found']}")
        print(f"   Pages: {summary['pages_crawled']}")
        print(f"   Screenshots: {summary['screenshots']}")
        print(f"   Forms: {summary['forms_found']}")
        print(f"   Tech: {', '.join(summary['tech_detected'][:5])}")
    
    def save_report(self):
        """Save final JSON report"""
        filename = f"{OUTPUT_DIR}/swarm_report_{self.target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Report: {filename}")
        
        # Also save markdown summary
        self.save_markdown_report(filename.replace(".json", ".md"))
    
    def save_markdown_report(self, filename):
        """Save human-readable markdown report"""
        summary = self.results.get("summary", {})
        
        md = f"""# Bug Bounty Report - {self.target}

**Generated:** {self.results['timestamp']}

## Summary

| Metric | Count |
|--------|-------|
| Subdomains | {summary.get('subdomains_found', 0)} |
| Pages Crawled | {summary.get('pages_crawled', 0)} |
| Screenshots | {summary.get('screenshots', 0)} |
| Forms | {summary.get('forms_found', 0)} |
| JS Files | {summary.get('js_files', 0)} |

## Technologies Detected

{', '.join(summary.get('tech_detected', ['None detected']))}

## Recon Findings

"""
        
        # Add subdomains
        if self.results.get("recon", {}).get("subdomains"):
            md += "### Subdomains\n\n"
            for sub in self.results["recon"]["subdomains"][:20]:
                md += f"- {sub}\n"
            md += "\n"
        
        # Add pages
        if self.results.get("crawl", {}).get("pages"):
            md += "### Crawled Pages\n\n"
            for page in self.results["crawl"]["pages"][:10]:
                md += f"- [{page.get('title', 'No title')}]({page.get('url')}) - {page.get('forms_count')} forms\n"
            md += "\n"
        
        # Add forms
        if self.results.get("crawl", {}).get("forms"):
            md += "### Forms Found\n\n"
            for form in self.results["crawl"]["forms"][:10]:
                md += f"- {form.get('method', 'GET').upper()} {form.get('action', '/')} ({len(form.get('inputs', []))} inputs)\n"
            md += "\n"
        
        # Screenshots
        if self.results.get("crawl", {}).get("screenshots"):
            md += "### Screenshots\n\n"
            for ss in self.results["crawl"]["screenshots"]:
                md += f"- `{ss.get('name')}`: {ss.get('path')}\n"
        
        with open(filename, "w") as f:
            f.write(md)
        
        print(f"📝 Markdown: {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python swarm_orchestrator.py <target_domain>")
        print("Example: python swarm_orchestrator.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    orchestrator = SwarmOrchestrator(target)
    results = orchestrator.run_full_swarm()
