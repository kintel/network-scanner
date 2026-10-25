#!/usr/bin/env python3
"""
CLI wrapper for backward compatibility with existing systemd service and scripts.
Delegates to network_scanner.main().
"""

import sys

from network_scanner import main

if __name__ == "__main__":
    sys.exit(main())

