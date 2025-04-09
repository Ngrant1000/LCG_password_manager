#!/usr/bin/env python3
"""
Test runner script for LCG Password Manager
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run tests for LCG Password Manager")
    parser.add_argument(
        "--unit", action="store_true", help="Run only unit tests"
    )
    parser.add_argument(
        "--integration", action="store_true", help="Run only integration tests"
    )
    parser.add_argument(
        "--gui", action="store_true", help="Run only GUI tests"
    )
    parser.add_argument(
        "--coverage", action="store_true", help="Generate coverage report"
    )
    parser.add_argument(
        "--parallel", action="store_true", help="Run tests in parallel"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Verbose output"
    )
    parser.add_argument(
        "--test-path", type=str, help="Path to specific test file or directory"
    )
    return parser.parse_args()

def run_tests(args):
    """Run tests based on command line arguments."""
    # Base command
    cmd = ["pytest"]
    
    # Add verbosity
    if args.verbose:
        cmd.append("-v")
    
    # Add parallel execution
    if args.parallel:
        cmd.append("-n")
        cmd.append("auto")
    
    # Add coverage if requested
    if args.coverage:
        cmd.append("--cov=src/lcg_password_manager")
        cmd.append("--cov-report=term")
        cmd.append("--cov-report=html")
        cmd.append("--cov-report=xml")
    
    # Add test type filters
    if args.unit:
        cmd.append("tests/unit")
    elif args.integration:
        cmd.append("tests/integration")
    elif args.gui:
        cmd.append("-m")
        cmd.append("gui")
    elif args.test_path:
        cmd.append(args.test_path)
    else:
        # Run all tests by default
        cmd.append("tests")
    
    # Print command
    print(f"Running command: {' '.join(cmd)}")
    
    # Run tests
    result = subprocess.run(cmd)
    return result.returncode

def main():
    """Main entry point."""
    args = parse_args()
    return run_tests(args)

if __name__ == "__main__":
    sys.exit(main()) 