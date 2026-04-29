"""
PonSSH — Application Entry
Creates the pywebview window pointed at the UI HTML.
"""

import os
import sys
import logging
import webview

from core.api_bridge import PonSSHApi

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
)
logger = logging.getLogger("ponssh.app")


class PonSSHApp:
    def __init__(self):
        self.api = PonSSHApi()
        self._ui_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "ui", "index.html"
        )

    def run(self):
        logger.info("Starting PonSSH...")
        window = webview.create_window(
            title="PonSSH",
            url=f"file://{self._ui_path}",
            js_api=self.api,
            width=1400,
            height=860,
            min_size=(900, 600),
            background_color="#050a0f",
            frameless=False,
        )

        def on_closing():
            logger.info("Window closing — disconnecting all sessions")
            self.api.disconnect_all()

        window.events.closing += on_closing

        webview.start(
            debug=("--debug" in sys.argv),
            private_mode=False,
        )
