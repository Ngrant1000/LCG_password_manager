#!/usr/bin/env python3
"""
LCG Password Manager - Dependency Vulnerability Checker

This script checks the project dependencies for known security vulnerabilities.
"""

import os
import sys
import json
import argparse
import datetime
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

class DependencyChecker:
    """Checker for dependency vulnerabilities."""
    
    def __init__(self, output_dir: Optional[str] = None):
        """Initialize the dependency checker with an optional output directory."""
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent.parent / "reports"
        self.output_dir.mkdir(exist_ok=True)
        self.results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "1.0.0",
            "dependencies": []
        }
    
    def check_dependencies(self) -> Dict[str, Any]:
        """Check all dependencies for vulnerabilities."""
        print("Checking dependencies for vulnerabilities...")
        
        # Check pip dependencies
        self.check_pip_dependencies()
        
        # Check for outdated packages
        self.check_outdated_packages()
        
        # Save the results
        self.save_results()
        
        return self.results
    
    def check_pip_dependencies(self) -> None:
        """Check pip dependencies for known vulnerabilities."""
        print("Checking pip dependencies...")
        
        try:
            # Run safety check if available
            try:
                result = subprocess.run(
                    ["safety", "check", "--json"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0:
                    # No vulnerabilities found
                    self.results["safety_check"] = {
                        "status": "pass",
                        "vulnerabilities": []
                    }
                else:
                    # Parse the JSON output
                    try:
                        vulns = json.loads(result.stdout)
                        self.results["safety_check"] = {
                            "status": "fail",
                            "vulnerabilities": vulns
                        }
                    except json.JSONDecodeError:
                        # If JSON parsing fails, try to parse the text output
                        vulns = []
                        for line in result.stdout.split("\n"):
                            if line.strip():
                                vulns.append({"package": line.strip()})
                        
                        self.results["safety_check"] = {
                            "status": "fail",
                            "vulnerabilities": vulns
                        }
            except FileNotFoundError:
                # Safety is not installed
                self.results["safety_check"] = {
                    "status": "error",
                    "message": "Safety is not installed. Install it with 'pip install safety'.",
                    "vulnerabilities": []
                }
            
            # Run pip-audit if available
            try:
                result = subprocess.run(
                    ["pip-audit", "--json"],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0:
                    # Parse the JSON output
                    try:
                        audit_data = json.loads(result.stdout)
                        self.results["pip_audit"] = {
                            "status": "pass" if not audit_data.get("vulnerabilities") else "fail",
                            "vulnerabilities": audit_data.get("vulnerabilities", [])
                        }
                    except json.JSONDecodeError:
                        self.results["pip_audit"] = {
                            "status": "error",
                            "message": "Failed to parse pip-audit output",
                            "vulnerabilities": []
                        }
                else:
                    self.results["pip_audit"] = {
                        "status": "error",
                        "message": f"pip-audit failed with exit code {result.returncode}",
                        "vulnerabilities": []
                    }
            except FileNotFoundError:
                # pip-audit is not installed
                self.results["pip_audit"] = {
                    "status": "error",
                    "message": "pip-audit is not installed. Install it with 'pip install pip-audit'.",
                    "vulnerabilities": []
                }
            
            # Get installed packages
            result = subprocess.run(
                ["pip", "freeze"],
                capture_output=True,
                text=True,
                check=True
            )
            
            installed_packages = []
            for line in result.stdout.split("\n"):
                if line.strip():
                    installed_packages.append(line.strip())
            
            self.results["installed_packages"] = installed_packages
            
        except subprocess.CalledProcessError as e:
            print(f"Error checking pip dependencies: {str(e)}")
            self.results["pip_check"] = {
                "status": "error",
                "message": str(e),
                "vulnerabilities": []
            }
    
    def check_outdated_packages(self) -> None:
        """Check for outdated packages."""
        print("Checking for outdated packages...")
        
        try:
            result = subprocess.run(
                ["pip", "list", "--outdated", "--format=json"],
                capture_output=True,
                text=True,
                check=True
            )
            
            outdated_packages = json.loads(result.stdout)
            self.results["outdated_packages"] = outdated_packages
            
        except subprocess.CalledProcessError as e:
            print(f"Error checking outdated packages: {str(e)}")
            self.results["outdated_packages"] = []
        except json.JSONDecodeError:
            print("Error parsing outdated packages output")
            self.results["outdated_packages"] = []
    
    def save_results(self) -> None:
        """Save the check results to a JSON file."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"dependency_check_{timestamp}.json"
        
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Dependency check results saved to {output_file}")
        
        # Also generate a human-readable report
        self.generate_report(output_file)
    
    def generate_report(self, output_file: Path) -> None:
        """Generate a human-readable report from the results."""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# LCG Password Manager - Dependency Check Report\n\n")
            f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Safety Check
            f.write("## Safety Check\n\n")
            safety_check = self.results.get("safety_check", {})
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
            f.write("## pip-audit\n\n")
            pip_audit = self.results.get("pip_audit", {})
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
            f.write("## Outdated Packages\n\n")
            outdated_packages = self.results.get("outdated_packages", [])
            if outdated_packages:
                f.write("[WARNING] The following packages are outdated:\n\n")
                f.write("| Package | Current Version | Latest Version |\n")
                f.write("|---------|----------------|----------------|\n")
                for pkg in outdated_packages:
                    f.write(f"| {pkg.get('name', 'Unknown')} | {pkg.get('version', 'Unknown')} | {pkg.get('latest_version', 'Unknown')} |\n")
                f.write("\n")
            else:
                f.write("[PASS] All packages are up to date.\n\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            
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
        
        print(f"Human-readable report generated at {output_file}")


def main():
    """Main entry point for the dependency checker."""
    parser = argparse.ArgumentParser(description="Check LCG Password Manager dependencies for vulnerabilities")
    parser.add_argument("--output", "-o", help="Output directory for check reports")
    args = parser.parse_args()
    
    checker = DependencyChecker(args.output)
    checker.check_dependencies()


if __name__ == "__main__":
    main() 