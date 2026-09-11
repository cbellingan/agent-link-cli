#!/usr/bin/env python3
"""Convenience entry point for local checkout: python3 cli.py ..."""
import sys
from agent_link.cli import main

if __name__ == "__main__":
    sys.exit(main())
