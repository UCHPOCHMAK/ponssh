#!/usr/bin/env python3
"""
PonSSH — Cyberpunk SSH Client
Entry point
"""
import sys
import os

# ── Vendor path (bundled dependencies) ──────────────────────────────
_root = os.path.dirname(os.path.abspath(__file__))
_vendor = os.path.join(_root, "vendor")
if os.path.isdir(_vendor):
    sys.path.insert(0, _vendor)

# Ensure project root is on path
sys.path.insert(0, _root)

from core.app import PonSSHApp

if __name__ == "__main__":
    app = PonSSHApp()
    app.run()
