"""
Lightweight deception / canary module for TrinTech-Guardian.
Spins up fake services on chosen ports that look real enough to attract scanners
and immediately feed connection events into the existing threat pipeline.
"""

import socket
import threading
import time
from typing import Callable, List, Dict, Optional


# Simple fake banners that look like real services
FAKE_BANNERS = {
    21: b"220 (vsFTPd 3.0.3)\r\n",
    23: b"Ubuntu 20.04.6 LTS\r\nlogin: ",
    3306: b"J\x00\x00\x00\x0a5.7.42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    6379: b"+PONG\r\n",
    27017: b"",  # Mongo — just accept and close
    11211: b"ERROR\r\n",  # memcached
}


class CanaryService:
    """A single fake service listener."""

    def __init__(self, port: int, banner: bytes, callback: Callable[[str, int], None]):
        self.port = port
        self.banner = banner
        self.callback = callback
        self._running = False
        self.thread: Optional[threading.Thread] = None
        self.hits = 0

    def start(self) -> bool:
        self._running = True
        self.thread = threading.Thread(target=self._serve, daemon=True, name=f"canary-{self.port}")
        self.thread.start()
        return True

    def stop(self):
        self._running = False

    def _serve(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(1.0)
            s.bind(("0.0.0.0", self.port))
            s.listen(16)
            while self._running:
                try:
                    conn, addr = s.accept()
                    src_ip = addr[0]
                    self.hits += 1
                    try:
                        if self.banner:
                            conn.sendall(self.banner)
                        # Tiny delay to look more realistic
                        time.sleep(0.05)
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
                    try:
                        self.callback(src_ip, self.port)
                    except Exception:
                        pass
                except socket.timeout:
                    continue
                except Exception:
                    if not self._running:
                        break
            s.close()
        except OSError:
            # Port in use — skip
            pass


class DeceptionGrid:
    """Manages multiple canary services that feed the Guardian threat pipeline."""

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        callback: Optional[Callable[[str, int], None]] = None,
        enabled: bool = True,
    ):
        self.ports = ports or [21, 23, 3306, 6379, 27017]
        self.callback = callback or (lambda ip, port: None)
        self.enabled = enabled
        self.canaries: List[CanaryService] = []

    def start(self):
        if not self.enabled:
            return
        for port in self.ports:
            banner = FAKE_BANNERS.get(port, b"")
            c = CanaryService(port, banner, self.callback)
            if c.start():
                self.canaries.append(c)
        if self.canaries:
            print(f"[+] Deception Grid: ONLINE — canaries on {[c.port for c in self.canaries]}")

    def stop(self):
        for c in self.canaries:
            c.stop()

    def get_status(self) -> dict:
        return {
            "enabled": self.enabled,
            "active_canaries": [c.port for c in self.canaries],
            "total_hits": sum(c.hits for c in self.canaries),
        }
