"""
User-space port sensor for TrinTech-Guardian.
Binds unprivileged TCP listeners on high-risk ports to detect scanners
without requiring raw sockets (critical for Termux / PRoot).
"""

import socket
import threading
import time
from typing import Callable, List, Optional


class PortSensor:
    """Lightweight multi-port listener that reports connection attempts."""

    def __init__(
        self,
        callback_function: Callable[[str, int], None],
        ports: Optional[List[int]] = None,
        bind_address: str = "0.0.0.0",
    ):
        self.callback = callback_function
        self.ports = ports or [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443]
        self.bind_address = bind_address
        self.threads: List[threading.Thread] = []
        self._running = False
        self.active_ports: List[int] = []

    def _listen_port(self, port: int) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(1.0)
            s.bind((self.bind_address, port))
            s.listen(32)
            self.active_ports.append(port)

            while self._running:
                try:
                    conn, addr = s.accept()
                    src_ip = addr[0]
                    try:
                        self.callback(src_ip, port)
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
                except socket.timeout:
                    continue
                except Exception:
                    if not self._running:
                        break
                    time.sleep(0.1)

            s.close()
        except OSError:
            # Port already in use or permission issue — skip silently
            pass
        except Exception:
            pass

    def start(self) -> None:
        """Start listeners in background threads and block until stopped."""
        self._running = True
        print(f"[+] Sensor Engine: ONLINE — attempting ports {self.ports}")

        for port in self.ports:
            t = threading.Thread(
                target=self._listen_port, args=(port,), daemon=True, name=f"sensor-{port}"
            )
            t.start()
            self.threads.append(t)

        # Give threads a moment to bind
        time.sleep(0.4)
        if self.active_ports:
            print(f"[+] Actively listening on: {sorted(self.active_ports)}")
        else:
            print("[!] No ports could be bound (all in use or restricted). Running in monitor-only mode.")

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        self._running = False
        print("[*] Sensor engine shutting down...")

    def get_status(self) -> dict:
        return {
            "configured_ports": self.ports,
            "active_ports": sorted(self.active_ports),
            "running": self._running,
        }
