#!/usr/bin/env python3
"""
Vulnerability Scanner - Runs all vulnerability scanners
Coordinates XSS, SQLi, IDOR, SSRF, and Auth scanners
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add agents to path
AGENT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(AGENT_DIR))

from agents.vuln_scanners.xss_scanner import XSSScanner
from agents.vuln_scanners.sqli_scanner import SQLiScanner
from agents.vuln_scanners.idor_scanner import IDORScanner
from agents.vuln_scanners.ssrf_scanner import SSRFScanner
from agents.vuln_scanners.auth_scanner import AuthScanner

OUTPUT_DIR = "/home/sparky/.openclaw/workspace/bugbounty-swarm/output"

class VulnScannerOrchestrator:
    def __init__(self, target, crawl_data=None):
        self.target = target
        self.crawl_data = crawl_data or {}
        self.results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "scans": {},
            "total_findings": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        }
        
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    def run_all_scanners(self):
        """Run all vulnerability scanners"""
        print("\n" + "=" * 50)
        print("🎯 VULNERABILITY SCANNERS")
        print("=" * 50)
        
        forms = self.crawl_data.get("forms", [])
        endpoints = self.crawl_data.get("endpoints", [])
        
        # XSS Scanner
        print("\n[1/5] XSS Scanner...")
        try:
            xss = XSSScanner(self.target, forms, endpoints)
            xss_results = xss.scan()
            self.results["scans"]["xss"] = xss_results
            self.count_findings(xss_results)
        except Exception as e:
            print(f"   ❌ XSS failed: {e}")
        
        # SQLi Scanner
        print("\n[2/5] SQLi Scanner...")
        try:
            sqli = SQLiScanner(self.target, forms, endpoints)
            sqli_results = sqli.scan()
            self.results["scans"]["sqli"] = sqli_results
            self.count_findings(sqli_results)
        except Exception as e:
            print(f"   ❌ SQLi failed: {e}")
        
        # IDOR Scanner
        print("\n[3/5] IDOR Scanner...")
        try:
            idor = IDORScanner(self.target)
            idor_results = idor.scan()
            self.results["scans"]["idor"] = idor_results
            self.count_findings(idor_results)
        except Exception as e:
            print(f"   ❌ IDOR failed: {e}")
        
        # SSRF Scanner
        print("\n[4/5] SSRF Scanner...")
        try:
            ssrf = SSRFScanner(self.target, endpoints)
            ssrf_results = ssrf.scan()
            self.results["scans"]["ssrf"] = ssrf_results
            self.count_findings(ssrf_results)
        except Exception as e:
            print(f"   ❌ SSRF failed: {e}")
        
        # Auth Scanner
        print("\n[5/5] Auth Scanner...")
        try:
            auth = AuthScanner(self.target)
            auth_results = auth.scan()
            self.results["scans"]["auth"] = auth_results
            self.count_findings(auth_results)
        except Exception as e:
            print(f"   ❌ Auth failed: {e}")
        
        self.save_report()
        self.print_summary()
        
        return self.results
    
    def count_findings(self, findings):
        """Count findings by severity"""
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            if severity in self.results["by_severity"]:
                self.results["by_severity"][severity] += 1
            self.results["total_findings"] += 1
    
    def print_summary(self):
        """Print summary"""
        print("\n" + "=" * 50)
        print("📊 VULNERABILITY SCAN SUMMARY")
        print("=" * 50)
        print(f"Target: {self.target}")
        print(f"Total Findings: {self.results['total_findings']}")
        print(f"  CRITICAL: {self.results['by_severity']['CRITICAL']}")
        print(f"  HIGH: {self.results['by_severity']['HIGH']}")
        print(f"  MEDIUM: {self.results['by_severity']['MEDIUM']}")
        print(f"  LOW: {self.results['by_severity']['LOW']}")
        print("=" * 50)
    
    def save_report(self):
        """Save full report"""
        filename = f"{OUTPUT_DIR}/vuln_scan_{self.target.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Report: {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vuln_scanner_orchestrator.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = VulnScannerOrchestrator(target)
    scanner.run_all_scanners()
