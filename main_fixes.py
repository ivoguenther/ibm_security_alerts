#!/usr/bin/env python3
"""
Convenience entry point for the Remediation/Fixes PTF workflow.

Fetches IBM Security Bulletin entries for a query, fetches each node's page,
and parses the Remediation/Fixes PTF table. See --help for options, e.g.:

    python3 main_fixes.py "IBM i" --remediation --format table --limit 20
    python3 main_fixes.py "IBM i" --remediation -d ibm.db --flat-csv fixes.csv
"""

import sys
from ibm_security_bulletin.cli import main

if __name__ == "__main__":
    sys.exit(main())
