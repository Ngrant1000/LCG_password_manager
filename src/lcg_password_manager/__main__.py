#!/usr/bin/env python3
"""
LCG Password Manager - Main entry point
"""

import sys
from pathlib import Path

# Add the src directory to the Python path
src_path = str(Path(__file__).parent.parent.parent)
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from lcg_password_manager.gui import main

if __name__ == "__main__":
    main() 