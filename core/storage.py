"""
PonSSH — Session & Profile Storage
Persists sessions, bastion configs, port forwards to JSON
"""

import json
import os
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".ponssh"
SESSIONS_FILE = CONFIG_DIR / "sessions.json"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _ensure_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_sessions() -> list[dict]:
    _ensure_dir()
    if not SESSIONS_FILE.exists():
        return []
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_sessions(sessions: list[dict]):
    _ensure_dir()
    with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2, ensure_ascii=False)


def load_config() -> dict:
    _ensure_dir()
    defaults = {
        "keepalive_interval": 30,
        "keepalive_count_max": 5,
        "theme": "cyberpunk",
        "font_size": 14,
        "terminal_cols": 220,
        "terminal_rows": 50,
    }
    if not CONFIG_FILE.exists():
        return defaults
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            defaults.update(data)
            return defaults
    except Exception:
        return defaults


def save_config(cfg: dict):
    _ensure_dir()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def add_session(session: dict) -> list[dict]:
    sessions = load_sessions()
    # Update if same name exists
    for i, s in enumerate(sessions):
        if s.get("name") == session.get("name"):
            sessions[i] = session
            save_sessions(sessions)
            return sessions
    sessions.append(session)
    save_sessions(sessions)
    return sessions


def delete_session(name: str) -> list[dict]:
    sessions = load_sessions()
    sessions = [s for s in sessions if s.get("name") != name]
    save_sessions(sessions)
    return sessions
