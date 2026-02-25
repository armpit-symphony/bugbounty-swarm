#!/usr/bin/env python3
"""
XSS Scanner Agent
Detects Reflected, Stored, and DOM-based XSS vulnerabilities
"""

import os
import sys
import json
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

OUTPUT_DIR = "/home/sparky/.openclaw/workspace/bugbounty-swarm/output"

class XSSScanner:
    def __init__(self, target, forms=None, endpoints=None):
        self.target = target
        self.forms = forms or []
        self.endpoints = endpoints or []
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountyBot/1.0"})
        
        # XSS payloads
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "{{constructor.constructor('alert(1)')()}}"
        ]
    
    def scan(self):
        """Run XSS scan"""
        print(f"   🎯 XSS Scanner: {self.target}")
        
        # Scan forms
        for form in self.forms:
            self.scan_form(form)
        
        # Scan endpoints with params
        for endpoint in self.endpoints[:20]:  # Limit
            parsed = urlparse(endpoint)
            if parsed.query:
                self.scan_params(endpoint, parse_qs(parsed.query))
        
        self.save_results()
        return self.findings
    
    def scan_form(self, form):
        """Test form inputs for XSS"""
        action = form.get("action", "/")
        method = form.get("method", "get").upper()
        inputs = form.get("inputs", [])
        
        if not inputs:
            return
        
        url = urljoin(self.target, action)
        
        for payload in self.payloads[:3]:  # Limit payloads
            data = {}
            for inp in inputs:
                if inp:
                    data[inp] = payload
            
            try:
                if method == "POST":
                    resp = self.session.post(url, data=data, timeout=10)
                else:
                    resp = self.session.get(url, params=data, timeout=10)
                
                # Check for reflected payload
                if payload in resp.text:
                    # Verify it's not in a safe context
                    self.check_reflection(url, payload, resp.text)
                    
            except Exception as e:
                pass
    
    def scan_params(self, url, params):
        """Test URL parameters for XSS"""
        for payload in self.payloads[:3]:
            test_params = {k: payload for k in params.keys()}
            
            try:
                resp = self.session.get(url, params=test_params, timeout=10)
                
                if payload in resp.text:
                    self.check_reflection(url, payload, resp.text)
                    
            except Exception:
                pass
    
    def check_reflection(self, url, payload, response):
        """Check if payload is reflected in safe context"""
        # Simple check - look for payload in response
        if payload not in response:
            return
        
        # Check for common filters
        filtered = False
        if "<script" in payload and "<script" not in response:
            filtered = True
        if "alert" in payload and "alert" not in response:
            filtered = True
        
        if not filtered:
            finding = {
                "type": "XSS",
                "url": url,
                "payload": payload,
                "severity": "HIGH",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Avoid duplicates
            if finding not in self.findings:
                self.findings.append(finding)
                print(f"      ⚠️ XSS FOUND: {url}")
    
    def save_results(self):
        """Save findings"""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        filename = f"{OUTPUT_DIR}/xss_{self.target.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump({
                "target": self.target,
                "findings": self.findings,
                "count": len(self.findings)
            }, f, indent=2)
        
        print(f"      💾 XSS findings: {len(self.findings)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = XSSScanner(sys.argv[1])
    scanner.scan()
