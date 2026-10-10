#!/usr/bin/env python3
"""
Entry point for running the IBM Security Bulletin CVE Extractor directly.
"""

import sys
from ibm_security_bulletin.cli import main

if __name__ == "__main__":
    sys.exit(main())
