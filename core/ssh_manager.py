
"""
PonSSH — SSH Connection Manager

Handles:
- Direct SSH connections
- Bastion / jump-host (Wallix-style) with password + TOTP 2FA
- SFTP through bastion
- Keepalive
- Remote / local port forwarding
- Shell channel with streaming output
"""

import threading
import time
import socket
import select
import queue
import logging
from typing import Callable, Optional

import paramiko

logger = logging.getLogger("ponssh.ssh")


class PortForwardThread(threading.Thread):
    """Generic TCP tunnel thread (local or remote forwarding)."""

    def __init__(self, transport: paramiko.Transport,
                 local_host: str, local_port: int,
                 remote_host: str, remote_port: int,
                 direction: str = "local"):
        super().__init__(daemon=True)
        self.transport = transport
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.direction = direction
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        if self.direction == "local":
            self._local_forward()
        else:
            self._remote_forward()

    def _local_forward(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.local_host, self.local_port))
            srv.listen(10)
            srv.settimeout(1)
            while not self._stop_event.is_set():
                try:
                    client_sock, _ = srv.accept()
                except socket.timeout:
                    continue
                chan = self.transport.open_channel(
                    "direct-tcpip",
                    (self.remote_host, self.remote_port),
                    (self.local_host, self.local_port)
                )
                t = threading.Thread(
                    target=self._tunnel, args=(client_sock, chan), daemon=True
                )
                t.start()
        finally:
            srv.close()

    def _remote_forward(self):
        self.transport.request_port_forward(self.remote_host, self.remote_port)
        while not self._stop_event.is_set():
            chan = self.transport.accept(timeout=1)
            if chan is None:
                continue
            sock = socket.create_connection((self.local_host, self.local_port))
            t = threading.Thread(
                target=self._tunnel, args=(sock, chan), daemon=True
            )
            t.start()

    @staticmethod
    def _tunnel(sock, chan):
        try:
            while True:
                r, _, _ = select.select([sock, chan], [], [], 5)
                if sock in r:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(4096)
                    if not data:
                        break
                    sock.send(data)
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
            try:
                chan.close()
            except Exception:
                pass


class SSHSession:
    """A single SSH session, potentially through a bastion host."""

    def __init__(self, profile: dict, output_callback: Callable = None):
        self.profile = profile
        self.output_cb = output_callback or (lambda x: None)
        self.bastion_client: Optional[paramiko.SSHClient] = None
        self.target_client: Optional[paramiko.SSHClient] = None
        self.shell_channel: Optional[paramiko.Channel] = None
        self._port_forwards: list = []
        self._keepalive_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._output_queue: queue.Queue = queue.Queue()
        self._connected = False
        self._sftp: Optional[paramiko.SFTPClient] = None

    # ------------------------------------------------------------------ #
    # Connect #
    # ------------------------------------------------------------------ #

    def connect(self, totp_code: str = ""):
        p = self.profile
        if p.get("use_bastion"):
            self._connect_bastion(totp_code)
        else:
            self._connect_direct()
        self._connected = True
        self._start_keepalive()
        self._setup_port_forwards()

    def _make_client(self) -> paramiko.SSHClient:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return c

    def _connect_direct(self):
        p = self.profile
        client = self._make_client()
        kwargs = dict(
            hostname=p["host"],
            port=int(p.get("port", 22)),
            username=p["username"],
            timeout=15,
        )
        if p.get("key_path"):
            kwargs["key_filename"] = p["key_path"]
        else:
            kwargs["password"] = p.get("password", "")

        client.connect(**kwargs)
        self.target_client = client

    def _connect_bastion(self, totp_code: str):
        p = self.profile
        b = p["bastion"]

        # Step 1: connect to bastion
        bastion = self._make_client()
        bpass = b.get("password", "")

        bastion.connect(
            hostname=b["host"],
            port=int(b.get("port", 22)),
            username=b["username"],
            password=bpass,
            timeout=15,
            look_for_keys=False,
            allow_agent=False,
        )

        # Handle keyboard-interactive 2FA if needed
        transport = bastion.get_transport()
        if not transport.is_authenticated():
            transport.auth_interactive(
                b["username"],
                self._kb_interactive_handler(totp_code)
            )

        self.bastion_client = bastion

        # Step 2: open tunnel through bastion to target
        transport = bastion.get_transport()
        dest_addr = (p["host"], int(p.get("port", 22)))
        src_addr = ("127.0.0.1", 0)
        sock = transport.open_channel("direct-tcpip", dest_addr, src_addr)

        # Step 3: connect target over the tunnel socket
        target = self._make_client()
        kwargs = dict(
            hostname=p["host"],
            port=int(p.get("port", 22)),
            username=p["username"],
            sock=sock,
            timeout=15,
        )
        if p.get("key_path"):
            kwargs["key_filename"] = p["key_path"]
        else:
            kwargs["password"] = p.get("password", "")

        target.connect(**kwargs)
        self.target_client = target

    @staticmethod
    def _kb_interactive_handler(totp_code: str):
        def handler(title, instructions, prompts):
            responses = []
            for prompt, echo in prompts:
                pl = prompt.lower()
                if any(kw in pl for kw in ("verification", "token", "code", "otp", "2fa")):
                    responses.append(totp_code)
                else:
                    responses.append("")
            return responses
        return handler

    # ------------------------------------------------------------------ #
    # Shell #
    # ------------------------------------------------------------------ #

    def open_shell(self) -> paramiko.Channel:
        transport = self.target_client.get_transport()
        chan = transport.open_session()
        p = self.profile
        chan.get_pty(
            term="xterm-256color",
            width=int(p.get("cols", 220)),
            height=int(p.get("rows", 50)),
        )
        chan.invoke_shell()
        self.shell_channel = chan
        return chan

    def send_command(self, cmd: str):
        if self.shell_channel and not self.shell_channel.closed:
            self.shell_channel.send(cmd)

    def resize_pty(self, cols: int, rows: int):
        if self.shell_channel and not self.shell_channel.closed:
            self.shell_channel.resize_pty(width=cols, height=rows)

    # ------------------------------------------------------------------ #
    # SFTP #
    # ------------------------------------------------------------------ #

    def get_sftp(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            self._sftp = self.target_client.open_sftp()
        return self._sftp

    def sftp_list(self, path: str = ".") -> list:
        sftp = self.get_sftp()
        items = []
        for attr in sftp.listdir_attr(path):
            items.append({
                "name": attr.filename,
                "size": attr.st_size,
                "mtime": attr.st_mtime,
                "is_dir": attr.st_mode is not None and (attr.st_mode & 0o40000) != 0,
            })
        return sorted(items, key=lambda x: (not x["is_dir"], x["name"].lower()))

    def sftp_download(self, remote_path: str, local_path: str,
                      progress_cb: Callable = None):
        sftp = self.get_sftp()
        sftp.get(remote_path, local_path, callback=progress_cb)

    def sftp_upload(self, local_path: str, remote_path: str,
                    progress_cb: Callable = None):
        sftp = self.get_sftp()
        sftp.put(local_path, remote_path, callback=progress_cb)

    def sftp_mkdir(self, path: str):
        self.get_sftp().mkdir(path)

    def sftp_remove(self, path: str):
        self.get_sftp().remove(path)

    def sftp_rename(self, old: str, new: str):
        self.get_sftp().rename(old, new)

    # ------------------------------------------------------------------ #
    # Keepalive #
    # ------------------------------------------------------------------ #

    def _start_keepalive(self):
        interval = int(self.profile.get("keepalive_interval", 30))
        if interval <= 0:
            return
        t = threading.Thread(
            target=self._keepalive_loop, args=(interval,), daemon=True
        )
        t.start()
        self._keepalive_thread = t

    def _keepalive_loop(self, interval: int):
        while not self._stop_event.is_set():
            time.sleep(interval)
            if self._stop_event.is_set():
                break
            try:
                t = self.target_client.get_transport()
                if t and t.is_active():
                    t.send_ignore()
            except Exception as e:
                logger.warning(f"Keepalive failed: {e}")
                break

    # ------------------------------------------------------------------ #
    # Port Forwarding #
    # ------------------------------------------------------------------ #

    def _setup_port_forwards(self):
        forwards = self.profile.get("port_forwards", [])
        transport = self.target_client.get_transport()
        for fwd in forwards:
            if not fwd.get("enabled", True):
                continue
            direction = fwd.get("direction", "local")
            t = PortForwardThread(
                transport=transport,
                local_host=fwd.get("local_host", "127.0.0.1"),
                local_port=int(fwd.get("local_port", 8080)),
                remote_host=fwd.get("remote_host", "127.0.0.1"),
                remote_port=int(fwd.get("remote_port", 8080)),
                direction=direction,
            )
            t.start()
            self._port_forwards.append(t)

    def add_port_forward(self, fwd: dict):
        transport = self.target_client.get_transport()
        t = PortForwardThread(
            transport=transport,
            local_host=fwd.get("local_host", "127.0.0.1"),
            local_port=int(fwd.get("local_port", 8080)),
            remote_host=fwd.get("remote_host", "127.0.0.1"),
            remote_port=int(fwd.get("remote_port", 8080)),
            direction=fwd.get("direction", "local"),
        )
        t.start()
        self._port_forwards.append(t)
        return t

    # ------------------------------------------------------------------ #
    # Disconnect #
    # ------------------------------------------------------------------ #

    def disconnect(self):
        self._stop_event.set()
        for fwd in self._port_forwards:
            fwd.stop()
        if self._sftp:
            try:
                self._sftp.close()
            except Exception:
                pass
        if self.shell_channel:
            try:
                self.shell_channel.close()
            except Exception:
                pass
        if self.target_client:
            try:
                self.target_client.close()
            except Exception:
                pass
        if self.bastion_client:
            try:
                self.bastion_client.close()
            except Exception:
                pass
        self._connected = False

    @property
    def is_connected(self) -> bool:
        if not self._connected:
            return False
        try:
            t = self.target_client.get_transport()
            return t is not None and t.is_active()
        except Exception:
            return False
