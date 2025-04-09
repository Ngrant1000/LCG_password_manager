#!/usr/bin/env python3
"""
LCG Password Manager - Security Audit Tool

This script performs comprehensive security audits of the LCG Password Manager,
checking various security features and generating detailed reports.
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

# Import the modules we need to audit
from src.lcg_password_manager import encryption_utils
from src.lcg_password_manager import security_utils
from src.lcg_password_manager import audit_logger
from src.lcg_password_manager import data_manager
from src.lcg_password_manager import two_factor
from src.lcg_password_manager import biometric_auth

class SecurityAudit:
    """Main security audit class that orchestrates all security checks."""
    
    def __init__(self, output_dir: Optional[str] = None):
        """Initialize the security audit with an optional output directory."""
        self.output_dir = Path(output_dir) if output_dir else Path(__file__).parent.parent / "reports"
        self.output_dir.mkdir(exist_ok=True)
        self.results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "1.0.0",
            "checks": {}
        }
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all security checks and return the results."""
        print("Starting comprehensive security audit...")
        
        # Run each check and store the results
        self.results["checks"]["encryption"] = self.check_encryption()
        self.results["checks"]["key_management"] = self.check_key_management()
        self.results["checks"]["audit_logging"] = self.check_audit_logging()
        self.results["checks"]["data_protection"] = self.check_data_protection()
        self.results["checks"]["authentication"] = self.check_authentication()
        self.results["checks"]["file_permissions"] = self.check_file_permissions()
        self.results["checks"]["memory_safety"] = self.check_memory_safety()
        
        # Calculate overall security score
        self.calculate_security_score()
        
        # Save the results
        self.save_results()
        
        return self.results
    
    def check_encryption(self) -> Dict[str, Any]:
        """Check encryption implementation and strength."""
        print("Checking encryption implementation...")
        results = {
            "status": "pass",
            "details": [],
            "recommendations": []
        }
        
        # Check AES implementation
        try:
            # Verify AES-256 is being used
            if hasattr(encryption_utils, "AES_KEY_SIZE") and encryption_utils.AES_KEY_SIZE == 32:
                results["details"].append("AES-256 encryption is properly configured")
            else:
                results["status"] = "fail"
                results["details"].append("AES-256 encryption is not properly configured")
                results["recommendations"].append("Ensure AES-256 (32 bytes) is used for encryption")
            
            # Check salt generation
            if hasattr(encryption_utils, "generate_salt") and callable(encryption_utils.generate_salt):
                salt = encryption_utils.generate_salt()
                if len(salt) >= 16:
                    results["details"].append("Salt generation is properly implemented")
                else:
                    results["status"] = "fail"
                    results["details"].append("Salt length is insufficient")
                    results["recommendations"].append("Increase salt length to at least 16 bytes")
            else:
                results["status"] = "fail"
                results["details"].append("Salt generation function not found")
                results["recommendations"].append("Implement proper salt generation")
            
            # Check key derivation
            if hasattr(encryption_utils, "derive_key") and callable(encryption_utils.derive_key):
                results["details"].append("Key derivation function is implemented")
            else:
                results["status"] = "fail"
                results["details"].append("Key derivation function not found")
                results["recommendations"].append("Implement proper key derivation using PBKDF2 or Argon2")
            
        except Exception as e:
            results["status"] = "error"
            results["details"].append(f"Error checking encryption: {str(e)}")
        
        return results
    
    def check_key_management(self) -> Dict[str, Any]:
        """Check key management practices."""
        print("Checking key management...")
        results = {
            "status": "pass",
            "details": [],
            "recommendations": []
        }
        
        # Check if keys are properly wiped from memory
        if hasattr(security_utils, "secure_wipe") and callable(security_utils.secure_wipe):
            results["details"].append("Secure memory wiping is implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Secure memory wiping not implemented")
            results["recommendations"].append("Implement secure memory wiping for sensitive data")
        
        # Check if keys are stored securely
        if hasattr(data_manager, "DataManager") and hasattr(data_manager.DataManager, "store_key"):
            results["details"].append("Key storage mechanism is implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Key storage mechanism not found")
            results["recommendations"].append("Implement secure key storage")
        
        return results
    
    def check_audit_logging(self) -> Dict[str, Any]:
        """Check audit logging implementation."""
        print("Checking audit logging...")
        results = {
            "status": "pass",
            "details": [],
            "recommendations": []
        }
        
        # Check if audit logger is properly implemented
        if hasattr(audit_logger, "AuditLogger") and hasattr(audit_logger.AuditLogger, "log_event"):
            results["details"].append("Audit logging is implemented")
            
            # Check if logs are encrypted
            if hasattr(audit_logger.AuditLogger, "encrypt_log"):
                results["details"].append("Audit logs are encrypted")
            else:
                results["status"] = "fail"
                results["details"].append("Audit logs are not encrypted")
                results["recommendations"].append("Implement encryption for audit logs")
            
            # Check if log integrity is verified
            if hasattr(audit_logger.AuditLogger, "verify_integrity"):
                results["details"].append("Log integrity verification is implemented")
            else:
                results["status"] = "fail"
                results["details"].append("Log integrity verification not implemented")
                results["recommendations"].append("Implement integrity verification for audit logs")
        else:
            results["status"] = "fail"
            results["details"].append("Audit logging not properly implemented")
            results["recommendations"].append("Implement comprehensive audit logging")
        
        return results
    
    def check_data_protection(self) -> Dict[str, Any]:
        """Check data protection mechanisms."""
        print("Checking data protection...")
        results = {
            "status": "pass",
            "details": [],
            "recommendations": []
        }
        
        # Check if data is properly encrypted at rest
        if hasattr(data_manager, "DataManager") and hasattr(data_manager.DataManager, "encrypt_data"):
            results["details"].append("Data encryption at rest is implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Data encryption at rest not implemented")
            results["recommendations"].append("Implement encryption for data at rest")
        
        # Check if clipboard is properly secured
        if hasattr(security_utils, "secure_clipboard") and callable(security_utils.secure_clipboard):
            results["details"].append("Secure clipboard handling is implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Secure clipboard handling not implemented")
            results["recommendations"].append("Implement secure clipboard handling with auto-clearing")
        
        return results
    
    def check_authentication(self) -> Dict[str, Any]:
        """Check authentication mechanisms."""
        print("Checking authentication...")
        results = {
            "status": "pass",
            "details": [],
            "recommendations": []
        }
        
        # Check master password protection
        if hasattr(security_utils, "verify_master_password") and callable(security_utils.verify_master_password):
            results["details"].append("Master password verification is implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Master password verification not implemented")
            results["recommendations"].append("Implement master password verification")
        
        # Check 2FA implementation
        if hasattr(two_factor, "TwoFactorAuth") and hasattr(two_factor.TwoFactorAuth, "verify_code"):
            results["details"].append("Two-factor authentication is implemented")
        else:
            results["status"] = "warn"
            results["details"].append("Two-factor authentication not implemented")
            results["recommendations"].append("Consider implementing two-factor authentication")
        
        # Check biometric authentication
        if hasattr(biometric_auth, "BiometricAuth") and hasattr(biometric_auth.BiometricAuth, "verify"):
            results["details"].append("Biometric authentication is implemented")
        else:
            results["status"] = "warn"
            results["details"].append("Biometric authentication not implemented")
            results["recommendations"].append("Consider implementing biometric authentication")
        
        # Check login attempt throttling
        if hasattr(security_utils, "check_login_attempts") and callable(security_utils.check_login_attempts):
            results["details"].append("Login attempt throttling is implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Login attempt throttling not implemented")
            results["recommendations"].append("Implement login attempt throttling")
        
        return results
    
    def check_file_permissions(self) -> Dict[str, Any]:
        """Check file permission settings."""
        print("Checking file permissions...")
        results = {
            "status": "pass",
            "details": [],
            "recommendations": []
        }
        
        # Check if file permissions are properly set
        if hasattr(security_utils, "set_secure_file_permissions") and callable(security_utils.set_secure_file_permissions):
            results["details"].append("Secure file permissions are implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Secure file permissions not implemented")
            results["recommendations"].append("Implement secure file permissions (600 on Unix, owner-only on Windows)")
        
        return results
    
    def check_memory_safety(self) -> Dict[str, Any]:
        """Check memory safety practices."""
        print("Checking memory safety...")
        results = {
            "status": "pass",
            "details": [],
            "recommendations": []
        }
        
        # Check if sensitive data is properly wiped from memory
        if hasattr(security_utils, "secure_wipe") and callable(security_utils.secure_wipe):
            results["details"].append("Secure memory wiping is implemented")
        else:
            results["status"] = "fail"
            results["details"].append("Secure memory wiping not implemented")
            results["recommendations"].append("Implement secure memory wiping for sensitive data")
        
        # Check if zero-copy operations are used where possible
        if hasattr(security_utils, "zero_copy_operation") and callable(security_utils.zero_copy_operation):
            results["details"].append("Zero-copy operations are implemented")
        else:
            results["status"] = "warn"
            results["details"].append("Zero-copy operations not implemented")
            results["recommendations"].append("Consider implementing zero-copy operations for sensitive data")
        
        return results
    
    def calculate_security_score(self) -> None:
        """Calculate an overall security score based on the results."""
        total_checks = len(self.results["checks"])
        passed_checks = sum(1 for check in self.results["checks"].values() if check["status"] == "pass")
        failed_checks = sum(1 for check in self.results["checks"].values() if check["status"] == "fail")
        warning_checks = sum(1 for check in self.results["checks"].values() if check["status"] == "warn")
        
        # Calculate score (0-100)
        score = int((passed_checks / total_checks) * 100)
        
        self.results["summary"] = {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "warning_checks": warning_checks,
            "security_score": score,
            "risk_level": "Low" if score >= 80 else "Medium" if score >= 60 else "High"
        }
    
    def save_results(self) -> None:
        """Save the audit results to a JSON file."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"security_audit_{timestamp}.json"
        
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Security audit results saved to {output_file}")
        
        # Also generate a human-readable report
        self.generate_report(output_file)

    def generate_report(self, json_file: Path) -> None:
        """Generate a human-readable report from the JSON results."""
        report_file = json_file.with_suffix(".md")
        
        with open(report_file, "w") as f:
            f.write("# LCG Password Manager - Security Audit Report\n\n")
            f.write(f"**Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary section
            f.write("## Summary\n\n")
            summary = self.results["summary"]
            f.write(f"- **Security Score:** {summary['security_score']}/100\n")
            f.write(f"- **Risk Level:** {summary['risk_level']}\n")
            f.write(f"- **Total Checks:** {summary['total_checks']}\n")
            f.write(f"- **Passed Checks:** {summary['passed_checks']}\n")
            f.write(f"- **Failed Checks:** {summary['failed_checks']}\n")
            f.write(f"- **Warning Checks:** {summary['warning_checks']}\n\n")
            
            # Detailed results section
            f.write("## Detailed Results\n\n")
            for check_name, check_result in self.results["checks"].items():
                status_emoji = "✅" if check_result["status"] == "pass" else "⚠️" if check_result["status"] == "warn" else "❌"
                f.write(f"### {status_emoji} {check_name.replace('_', ' ').title()}\n\n")
                f.write(f"**Status:** {check_result['status'].upper()}\n\n")
                
                if check_result["details"]:
                    f.write("**Details:**\n")
                    for detail in check_result["details"]:
                        f.write(f"- {detail}\n")
                    f.write("\n")
                
                if check_result["recommendations"]:
                    f.write("**Recommendations:**\n")
                    for rec in check_result["recommendations"]:
                        f.write(f"- {rec}\n")
                    f.write("\n")
            
            # Recommendations section
            f.write("## Overall Recommendations\n\n")
            all_recommendations = []
            for check_result in self.results["checks"].values():
                all_recommendations.extend(check_result["recommendations"])
            
            # Remove duplicates while preserving order
            unique_recommendations = []
            for rec in all_recommendations:
                if rec not in unique_recommendations:
                    unique_recommendations.append(rec)
            
            for rec in unique_recommendations:
                f.write(f"- {rec}\n")
        
        print(f"Human-readable report generated at {report_file}")


def main():
    """Main entry point for the security audit script."""
    parser = argparse.ArgumentParser(description="Run security audit for LCG Password Manager")
    parser.add_argument("--output", "-o", help="Output directory for audit reports")
    args = parser.parse_args()
    
    audit = SecurityAudit(args.output)
    audit.run_all_checks()


if __name__ == "__main__":
    main() 