#!/usr/bin/env python3
"""
LCG Password Manager - Comprehensive Security Audit

This script runs both the vulnerability scanner and dependency checker,
combining their results into a single comprehensive security report.
"""

import os
import sys
import json
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import the security audit modules
from security_audit.scripts.vulnerability_scan import VulnerabilityScanner
from security_audit.scripts.dependency_check import DependencyChecker

class SecurityAudit:
    """Comprehensive security audit that combines vulnerability scanning and dependency checking."""
    
    def __init__(self, output_dir: Optional[str] = None):
        """Initialize the security audit with an optional output directory."""
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent.parent / "reports"
        self.output_dir.mkdir(exist_ok=True)
        self.results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "1.0.0",
            "vulnerability_scan": {},
            "dependency_check": {}
        }
    
    def run_audit(self, scan_dir: Optional[str] = None) -> Dict[str, Any]:
        """Run the comprehensive security audit."""
        print("Starting comprehensive security audit...")
        
        # Run vulnerability scan
        print("\n=== Running Vulnerability Scan ===")
        scanner = VulnerabilityScanner(str(self.output_dir))
        self.results["vulnerability_scan"] = scanner.scan_codebase(scan_dir)
        
        # Run dependency check
        print("\n=== Running Dependency Check ===")
        checker = DependencyChecker(str(self.output_dir))
        self.results["dependency_check"] = checker.check_dependencies()
        
        # Save combined results
        self.save_results()
        
        # Generate comprehensive report
        self.generate_comprehensive_report()
        
        return self.results
    
    def save_results(self) -> None:
        """Save the combined audit results to a JSON file."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"security_audit_{timestamp}.json"
        
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nComprehensive security audit results saved to {output_file}")
    
    def generate_comprehensive_report(self) -> None:
        """Generate a comprehensive human-readable report from the combined results."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"security_audit_{timestamp}.md"
        
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("# LCG Password Manager - Comprehensive Security Audit Report\n\n")
            f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            
            # Vulnerability Scan Summary
            vuln_scan = self.results["vulnerability_scan"]
            vuln_summary = vuln_scan.get("summary", {})
            f.write("### Vulnerability Scan\n\n")
            f.write(f"- **Risk Score:** {vuln_summary.get('risk_score', 'N/A')}/100\n")
            f.write(f"- **Risk Level:** {vuln_summary.get('risk_level', 'N/A')}\n")
            f.write(f"- **Total Vulnerabilities:** {vuln_summary.get('total_vulnerabilities', 0)}\n")
            f.write(f"- **Critical Vulnerabilities:** {vuln_summary.get('severity_counts', {}).get('Critical', 0)}\n")
            f.write(f"- **High Vulnerabilities:** {vuln_summary.get('severity_counts', {}).get('High', 0)}\n")
            f.write(f"- **Medium Vulnerabilities:** {vuln_summary.get('severity_counts', {}).get('Medium', 0)}\n")
            f.write(f"- **Low Vulnerabilities:** {vuln_summary.get('severity_counts', {}).get('Low', 0)}\n\n")
            
            # Dependency Check Summary
            dep_check = self.results["dependency_check"]
            f.write("### Dependency Check\n\n")
            
            # Safety Check
            safety_check = dep_check.get("safety_check", {})
            if safety_check.get("status") == "pass":
                f.write("- [PASS] No vulnerabilities found with Safety.\n")
            elif safety_check.get("status") == "fail":
                f.write(f"- [FAIL] {len(safety_check.get('vulnerabilities', []))} vulnerabilities found with Safety.\n")
            else:
                f.write(f"- [WARNING] {safety_check.get('message', 'Safety check failed')}\n")
            
            # pip-audit
            pip_audit = dep_check.get("pip_audit", {})
            if pip_audit.get("status") == "pass":
                f.write("- [PASS] No vulnerabilities found with pip-audit.\n")
            elif pip_audit.get("status") == "fail":
                f.write(f"- [FAIL] {len(pip_audit.get('vulnerabilities', []))} vulnerabilities found with pip-audit.\n")
            else:
                f.write(f"- [WARNING] {pip_audit.get('message', 'pip-audit check failed')}\n")
            
            # Outdated Packages
            outdated_packages = dep_check.get("outdated_packages", [])
            f.write(f"- {'[PASS] All packages are up to date.' if not outdated_packages else f'[WARNING] {len(outdated_packages)} packages are outdated.'}\n\n")
            
            # Overall Security Assessment
            f.write("## Overall Security Assessment\n\n")
            
            # Determine overall risk level
            vuln_risk_level = vuln_summary.get("risk_level", "Unknown")
            dep_risk_level = "High" if (safety_check.get("status") == "fail" or pip_audit.get("status") == "fail") else "Medium" if outdated_packages else "Low"
            
            risk_levels = {
                "Critical": 4,
                "High": 3,
                "Medium": 2,
                "Low": 1
            }
            
            overall_risk_score = max(
                risk_levels.get(vuln_risk_level, 0),
                risk_levels.get(dep_risk_level, 0)
            )
            
            overall_risk_level = next(
                (level for level, score in risk_levels.items() if score == overall_risk_score),
                "Unknown"
            )
            
            f.write(f"**Overall Risk Level:** {overall_risk_level}\n\n")
            
            if overall_risk_level in ["Critical", "High"]:
                f.write("[WARNING] **Immediate action required.** The application has significant security vulnerabilities that need to be addressed.\n\n")
            elif overall_risk_level == "Medium":
                f.write("[WARNING] **Action recommended.** The application has some security issues that should be addressed.\n\n")
            else:
                f.write("[PASS] **Good security posture.** The application has minimal security issues.\n\n")
            
            # Detailed Findings
            f.write("## Detailed Findings\n\n")
            
            # Vulnerability Scan Details
            f.write("### Vulnerability Scan Details\n\n")
            
            # Group vulnerabilities by category
            categories = {}
            for vuln in vuln_scan.get("vulnerabilities", []):
                category = vuln.get("category", "Unknown")
                if category not in categories:
                    categories[category] = []
                categories[category].append(vuln)
            
            # Sort categories by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            sorted_categories = sorted(
                categories.keys(),
                key=lambda c: min(severity_order[v.get("severity", "Low")] for v in categories[c])
            )
            
            for category in sorted_categories:
                vulns = categories[category]
                # Sort vulnerabilities by severity
                vulns.sort(key=lambda v: severity_order[v.get("severity", "Low")])
                
                f.write(f"#### {category.replace('_', ' ').title()}\n\n")
                
                for vuln in vulns:
                    severity_text = "[CRITICAL]" if vuln.get("severity") == "Critical" else "[HIGH]" if vuln.get("severity") == "High" else "[MEDIUM]" if vuln.get("severity") == "Medium" else "[LOW]"
                    f.write(f"##### {severity_text} {vuln.get('description', 'Unknown vulnerability')}\n\n")
                    f.write(f"**Severity:** {vuln.get('severity', 'Unknown')}\n\n")
                    f.write(f"**File:** `{vuln.get('file', 'Unknown')}`\n\n")
                    f.write(f"**Line:** {vuln.get('line', 'Unknown')}\n\n")
                    f.write("**Code:**\n```python\n")
                    f.write(f"{vuln.get('line_content', '')}\n")
                    f.write("```\n\n")
                
                f.write("\n")
            
            # Dependency Check Details
            f.write("### Dependency Check Details\n\n")
            
            # Safety Check
            f.write("#### Safety Check\n\n")
            if safety_check.get("status") == "pass":
                f.write("[PASS] No vulnerabilities found with Safety.\n\n")
            elif safety_check.get("status") == "fail":
                f.write("[FAIL] Vulnerabilities found with Safety:\n\n")
                for vuln in safety_check.get("vulnerabilities", []):
                    if isinstance(vuln, dict):
                        f.write(f"- **{vuln.get('package', 'Unknown')}**: {vuln.get('description', 'No description available')}\n")
                    else:
                        f.write(f"- {vuln}\n")
                f.write("\n")
            else:
                f.write(f"[WARNING] {safety_check.get('message', 'Safety check failed')}\n\n")
            
            # pip-audit
            f.write("#### pip-audit\n\n")
            if pip_audit.get("status") == "pass":
                f.write("[PASS] No vulnerabilities found with pip-audit.\n\n")
            elif pip_audit.get("status") == "fail":
                f.write("[FAIL] Vulnerabilities found with pip-audit:\n\n")
                for vuln in pip_audit.get("vulnerabilities", []):
                    f.write(f"- **{vuln.get('package', 'Unknown')}**: {vuln.get('description', 'No description available')}\n")
                f.write("\n")
            else:
                f.write(f"[WARNING] {pip_audit.get('message', 'pip-audit check failed')}\n\n")
            
            # Outdated packages
            f.write("#### Outdated Packages\n\n")
            if outdated_packages:
                f.write("The following packages are outdated:\n\n")
                f.write("| Package | Current Version | Latest Version |\n")
                f.write("|---------|----------------|----------------|\n")
                for pkg in outdated_packages:
                    f.write(f"| {pkg.get('name', 'Unknown')} | {pkg.get('version', 'Unknown')} | {pkg.get('latest_version', 'Unknown')} |\n")
                f.write("\n")
            else:
                f.write("[PASS] All packages are up to date.\n\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            
            # Code vulnerability recommendations
            f.write("### Code Vulnerability Recommendations\n\n")
            
            recommendations = {
                "hardcoded_secrets": "Remove all hardcoded secrets and use environment variables or secure key management systems instead.",
                "insecure_random": "Replace insecure random number generation with cryptographically secure alternatives like `secrets` module.",
                "weak_crypto": "Replace weak cryptographic algorithms with strong alternatives (AES-256, SHA-256, etc.).",
                "sql_injection": "Use parameterized queries or ORM to prevent SQL injection vulnerabilities.",
                "command_injection": "Avoid using shell commands with user input. If necessary, use `shlex.quote()` to escape inputs.",
                "path_traversal": "Validate and sanitize file paths to prevent path traversal attacks.",
                "insecure_deserialization": "Avoid using pickle or yaml.load(). Use json.loads() or custom deserialization with validation.",
                "debug_code": "Remove all debug code that exposes sensitive information.",
                "insecure_defaults": "Use secure default permissions (0o600 for files, 0o700 for directories).",
                "missing_validation": "Implement proper input validation for all user inputs.",
            }
            
            for category in sorted_categories:
                if category in recommendations:
                    f.write(f"- **{category.replace('_', ' ').title()}:** {recommendations[category]}\n")
            
            f.write("\n")
            
            # Dependency recommendations
            f.write("### Dependency Recommendations\n\n")
            
            if safety_check.get("status") == "fail" or pip_audit.get("status") == "fail":
                f.write("1. Update vulnerable packages to their latest versions.\n")
                f.write("2. Consider using alternative packages if updates are not available.\n")
            
            if outdated_packages:
                f.write("3. Update outdated packages to their latest versions.\n")
                f.write("4. Test the application after updating to ensure compatibility.\n")
            
            if safety_check.get("status") == "error" or pip_audit.get("status") == "error":
                f.write("5. Install security scanning tools:\n")
                f.write("   - Safety: `pip install safety`\n")
                f.write("   - pip-audit: `pip install pip-audit`\n")
            
            f.write("\n")
            
            # Action Plan
            f.write("## Action Plan\n\n")
            
            if overall_risk_level in ["Critical", "High"]:
                f.write("### Immediate Actions (1-3 days)\n\n")
                f.write("1. Address all Critical and High severity vulnerabilities\n")
                f.write("2. Update all vulnerable dependencies\n")
                f.write("3. Conduct a code review focusing on security\n\n")
                
                f.write("### Short-term Actions (1-2 weeks)\n\n")
                f.write("1. Address Medium severity vulnerabilities\n")
                f.write("2. Update outdated dependencies\n")
                f.write("3. Implement automated security testing in CI/CD pipeline\n\n")
                
                f.write("### Long-term Actions (1-3 months)\n\n")
                f.write("1. Address Low severity vulnerabilities\n")
                f.write("2. Conduct a comprehensive security audit\n")
                f.write("3. Implement security monitoring and alerting\n")
            elif overall_risk_level == "Medium":
                f.write("### Immediate Actions (1 week)\n\n")
                f.write("1. Address all High severity vulnerabilities\n")
                f.write("2. Update all vulnerable dependencies\n\n")
                
                f.write("### Short-term Actions (2-4 weeks)\n\n")
                f.write("1. Address Medium severity vulnerabilities\n")
                f.write("2. Update outdated dependencies\n")
                f.write("3. Implement automated security testing in CI/CD pipeline\n\n")
                
                f.write("### Long-term Actions (2-3 months)\n\n")
                f.write("1. Address Low severity vulnerabilities\n")
                f.write("2. Conduct a comprehensive security audit\n")
                f.write("3. Implement security monitoring and alerting\n")
            else:
                f.write("### Immediate Actions (1-2 weeks)\n\n")
                f.write("1. Address any remaining Medium severity vulnerabilities\n")
                f.write("2. Update any outdated dependencies\n\n")
                
                f.write("### Short-term Actions (1-2 months)\n\n")
                f.write("1. Address Low severity vulnerabilities\n")
                f.write("2. Implement automated security testing in CI/CD pipeline\n\n")
                
                f.write("### Long-term Actions (3-6 months)\n\n")
                f.write("1. Conduct a comprehensive security audit\n")
                f.write("2. Implement security monitoring and alerting\n")
                f.write("3. Consider third-party security assessment\n")
        
        print(f"Comprehensive security report generated at {report_file}")


def main():
    """Main entry point for the comprehensive security audit."""
    parser = argparse.ArgumentParser(description="Run comprehensive security audit for LCG Password Manager")
    parser.add_argument("--directory", "-d", help="Directory to scan for vulnerabilities (default: src/lcg_password_manager)")
    parser.add_argument("--output", "-o", help="Output directory for audit reports")
    args = parser.parse_args()
    
    # Set default directory if not provided
    if not args.directory:
        args.directory = str(project_root / "src" / "lcg_password_manager")
    
    audit = SecurityAudit(args.output)
    audit.run_audit(args.directory)


if __name__ == "__main__":
    main() 