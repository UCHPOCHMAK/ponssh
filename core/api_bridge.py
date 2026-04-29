
"""
PonSSH — WebView API Bridge
All methods here are callable from JavaScript via window.pywebview.api.*
"""

import threading
import time
import os
import json
import queue
import logging
from typing import Optional

from core.ssh_manager import SSHSession
from core import storage

logger = logging.getLogger("ponssh.api")


class PonSSHApi:
    """Exposed to JS via pywebview."""

    def __init__(self):
        self._sessions: dict = {} # tab_id -> SSHSession
        self._output_queues: dict = {} # tab_id -> queue.Queue
        self._read_threads: dict = {} # tab_id -> Thread
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Sessions CRUD #
    # ------------------------------------------------------------------ #

    def get_sessions(self) -> list:
        return storage.load_sessions()

    def save_session(self, session: dict) -> dict:
        try:
            storage.add_session(session)
            return {"ok": True, "sessions": storage.load_sessions()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def delete_session(self, name: str) -> dict:
        try:
            storage.delete_session(name)
            return {"ok": True, "sessions": storage.load_sessions()}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_config(self) -> dict:
        return storage.load_config()

    def save_config(self, cfg: dict) -> dict:
        try:
            storage.save_config(cfg)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------ #
    # SSH Connect / Disconnect #
    # ------------------------------------------------------------------ #

    def connect(self, tab_id: str, profile: dict, totp_code: str = "") -> dict:
        try:
            session = SSHSession(profile)
            session.connect(totp_code=totp_code)

            with self._lock:
                self._sessions[tab_id] = session
                self._output_queues[tab_id] = queue.Queue()

            # open shell & start reader
            chan = session.open_shell()
            t = threading.Thread(
                target=self._read_loop,
                args=(tab_id, chan),
                daemon=True
            )
            t.start()

            with self._lock:
                self._read_threads[tab_id] = t

            return {"ok": True}
        except Exception as e:
            logger.exception("connect error")
            return {"ok": False, "error": str(e)}

    def disconnect(self, tab_id: str) -> dict:
        with self._lock:
            session = self._sessions.pop(tab_id, None)
            self._output_queues.pop(tab_id, None)
            self._read_threads.pop(tab_id, None)
        if session:
            session.disconnect()
        return {"ok": True}

    def disconnect_all(self):
        """Called on window close — disconnect all active sessions."""
        with self._lock:
            ids = list(self._sessions.keys())
            sessions = dict(self._sessions)
            self._sessions.clear()
            self._output_queues.clear()
            self._read_threads.clear()
        # Disconnect outside the lock to avoid deadlock
        for session in sessions.values():
            try:
                session.disconnect()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Terminal I/O #
    # ------------------------------------------------------------------ #

    def send_input(self, tab_id: str, data: str) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"ok": False, "error": "not connected"}
        try:
            session.send_command(data)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def resize_terminal(self, tab_id: str, cols: int, rows: int) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if session:
            session.resize_pty(cols, rows)
        return {"ok": True}

    def poll_output(self, tab_id: str) -> dict:
        """JS polls this to get buffered output."""
        with self._lock:
            q = self._output_queues.get(tab_id)
        if not q:
            return {"ok": False, "data": ""}
        chunks = []
        try:
            while True:
                chunks.append(q.get_nowait())
        except queue.Empty:
            pass
        return {"ok": True, "data": "".join(chunks)}

    def _read_loop(self, tab_id: str, chan):
        try:
            while True:
                if chan.closed:
                    break
                if chan.recv_ready():
                    data = chan.recv(8192).decode("utf-8", errors="replace")
                    with self._lock:
                        q = self._output_queues.get(tab_id)
                    if q:
                        q.put(data)
                else:
                    time.sleep(0.02)
        except Exception as e:
            logger.debug(f"read loop ended: {e}")
        finally:
            with self._lock:
                q = self._output_queues.get(tab_id)
            if q:
                q.put("\r\n\x1b[31m[PonSSH] Connection closed.\x1b[0m\r\n")

    # ------------------------------------------------------------------ #
    # SFTP #
    # ------------------------------------------------------------------ #

    def sftp_list(self, tab_id: str, path: str = ".") -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"ok": False, "error": "not connected"}
        try:
            items = session.sftp_list(path)
            return {"ok": True, "items": items}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def sftp_download(self, tab_id: str, remote_path: str, local_path: str) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"ok": False, "error": "not connected"}
        try:
            session.sftp_download(remote_path, local_path)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def sftp_upload(self, tab_id: str, local_path: str, remote_path: str) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"ok": False, "error": "not connected"}
        try:
            session.sftp_upload(local_path, remote_path)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def sftp_mkdir(self, tab_id: str, path: str) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"ok": False, "error": "not connected"}
        try:
            session.sftp_mkdir(path)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def sftp_remove(self, tab_id: str, path: str) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"ok": False, "error": "not connected"}
        try:
            session.sftp_remove(path)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------ #
    # Port Forwarding #
    # ------------------------------------------------------------------ #

    def add_port_forward(self, tab_id: str, fwd: dict) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"ok": False, "error": "not connected"}
        try:
            session.add_port_forward(fwd)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------------ #
    # Status #
    # ------------------------------------------------------------------ #

    def get_status(self, tab_id: str) -> dict:
        with self._lock:
            session = self._sessions.get(tab_id)
        if not session:
            return {"connected": False}
        return {"connected": session.is_connected}
