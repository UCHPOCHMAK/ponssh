#!/usr/bin/env python3
"""
PonSSH — Cyberpunk SSH Client
Entry point
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.app import PonSSHApp

if __name__ == "__main__":
    app = PonSSHApp()
    app.run()
