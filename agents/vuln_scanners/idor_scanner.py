#!/usr/bin/env python3
"""
IDOR Scanner Agent
Detects Insecure Direct Object Reference vulnerabilities
"""

import os
import sys
import json
import requests
import re
from urllib.parse import urljoin, urlparse
from datetime import datetime

OUTPUT_DIR = "/home/sparky/.openclaw/workspace/bugbounty-swarm/output"

class IDORScanner:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountyBot/1.0"})
        
        # Common IDOR patterns
        self.id_patterns = [
            r'/user/(\d+)',
            r'/id/(\d+)',
            r'/profile/(\d+)',
            r'/post/(\d+)',
            r'/order/(\d+)',
            r'/invoice/(\d+)',
            r'/account/(\d+)',
            r'/api/(\d+)',
            r'/file/(\d+)',
            r'/resource/(\d+)',
            r'/item/(\d+)',
            r'/[a-z-]+/(\d+)'
        ]
    
    def scan(self):
        """Run IDOR scan"""
        print(f"   🎯 IDOR Scanner: {self.target}")
        
        # Extract potential IDOR endpoints from target
        endpoints = self.extract_idor_endpoints()
        
        # Test each endpoint
        for endpoint in endpoints[:10]:
            self.test_idor(endpoint)
        
        self.save_results()
        return self.findings
    
    def extract_idor_endpoints(self):
        """Extract endpoints that might have IDOR"""
        endpoints = []
        
        try:
            resp = self.session.get(self.target, timeout=10)
            
            # Find numeric patterns in URLs
            for pattern in self.id_patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                for match in matches:
                    # Replace ID with test value
                    endpoint = re.sub(pattern, f"/{match}/", self.target)
                    if endpoint not in endpoints:
                        endpoints.append(endpoint)
            
            # Also check hrefs
            hrefs = re.findall(r'href=["\'](/[^"\']+)["\']', resp.text)
            for href in hrefs:
                for pattern in self.id_patterns:
                    if re.search(pattern, href):
                        full_url = urljoin(self.target, href)
                        if full_url not in endpoints:
                            endpoints.append(full_url)
                            
        except Exception as e:
            print(f"      ⚠️ Error extracting: {e}")
        
        return endpoints
    
    def test_idor(self, endpoint):
        """Test endpoint for IDOR"""
        # Try different user IDs
        for test_id in [1, 2, 0, 999, "admin"]:
            try:
                # Replace the numeric part
                test_url = re.sub(r'/\d+/', f'/{test_id}/', endpoint)
                
                resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                
                # Check for unauthorized access
                # 200 with sensitive data = potential IDOR
                if resp.status_code == 200:
                    # Check for sensitive keywords
                    sensitive = ["email", "password", "address", "phone", "credit", 
                                "ssn", "invoice", "order", "private", "profile"]
                    
                    content_lower = resp.text.lower()
                    found_sensitive = [s for s in sensitive if s in content_lower]
                    
                    if found_sensitive:
                        finding = {
                            "type": "IDOR",
                            "url": test_url,
                            "test_id": test_id,
                            "indicators": found_sensitive,
                            "severity": "HIGH",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        
                        if finding not in self.findings:
                            self.findings.append(finding)
                            print(f"      ⚠️ IDOR FOUND: {test_url}")
                            return  # Found one, move on
                            
            except Exception:
                pass
    
    def save_results(self):
        """Save findings"""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        filename = f"{OUTPUT_DIR}/idor_{self.target.replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump({
                "target": self.target,
                "findings": self.findings,
                "count": len(self.findings)
            }, f, indent=2)
        
        print(f"      💾 IDOR findings: {len(self.findings)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python idor_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = IDORScanner(sys.argv[1])
    scanner.scan()
