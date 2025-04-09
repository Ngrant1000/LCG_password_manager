#!/usr/bin/env python3
"""
Packaging script for LCG Password Manager
"""

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Package LCG Password Manager")
    parser.add_argument(
        "--format", choices=["wheel", "sdist", "pyinstaller", "all"], 
        default="all", help="Package format"
    )
    parser.add_argument(
        "--clean", action="store_true", help="Clean build artifacts before packaging"
    )
    parser.add_argument(
        "--test", action="store_true", help="Run tests before packaging"
    )
    return parser.parse_args()

def clean_build_artifacts():
    """Clean build artifacts."""
    dirs_to_clean = ["build", "dist", "__pycache__", ".pytest_cache"]
    for dir_name in dirs_to_clean:
        if os.path.exists(dir_name):
            print(f"Cleaning {dir_name}...")
            shutil.rmtree(dir_name)
    
    # Clean .pyc files
    for root, dirs, files in os.walk("."):
        for file in files:
            if file.endswith(".pyc"):
                os.remove(os.path.join(root, file))

def run_tests():
    """Run tests before packaging."""
    print("Running tests...")
    result = subprocess.run(["python", "scripts/run_tests.py", "--coverage"])
    if result.returncode != 0:
        print("Tests failed. Aborting packaging.")
        sys.exit(1)
    print("Tests passed.")

def build_wheel():
    """Build wheel package."""
    print("Building wheel package...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", "wheel"])
    if result.returncode != 0:
        print("Failed to install wheel. Aborting.")
        sys.exit(1)
    
    result = subprocess.run([sys.executable, "setup.py", "bdist_wheel"])
    if result.returncode != 0:
        print("Failed to build wheel. Aborting.")
        sys.exit(1)
    print("Wheel package built successfully.")

def build_sdist():
    """Build source distribution."""
    print("Building source distribution...")
    result = subprocess.run([sys.executable, "setup.py", "sdist"])
    if result.returncode != 0:
        print("Failed to build source distribution. Aborting.")
        sys.exit(1)
    print("Source distribution built successfully.")

def build_pyinstaller():
    """Build executable using PyInstaller."""
    print("Building executable with PyInstaller...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"])
    if result.returncode != 0:
        print("Failed to install PyInstaller. Aborting.")
        sys.exit(1)
    
    # Use the spec file if it exists
    spec_file = "LCGPasswordManager_Modern.spec"
    if os.path.exists(spec_file):
        result = subprocess.run(["pyinstaller", spec_file])
    else:
        result = subprocess.run([
            "pyinstaller", 
            "--name=LCGPasswordManager", 
            "--windowed", 
            "--onefile", 
            "main.py"
        ])
    
    if result.returncode != 0:
        print("Failed to build executable. Aborting.")
        sys.exit(1)
    print("Executable built successfully.")

def main():
    """Main entry point."""
    args = parse_args()
    
    # Clean build artifacts if requested
    if args.clean:
        clean_build_artifacts()
    
    # Run tests if requested
    if args.test:
        run_tests()
    
    # Build packages based on format
    if args.format == "wheel" or args.format == "all":
        build_wheel()
    
    if args.format == "sdist" or args.format == "all":
        build_sdist()
    
    if args.format == "pyinstaller" or args.format == "all":
        build_pyinstaller()
    
    print("Packaging completed successfully.")

if __name__ == "__main__":
    main() 