"""
Fail-safe circuit breaker for TrinTech-Guardian.
Prevents accidental isolation of local infrastructure, gateways, and private ranges.
"""

import ipaddress
import socket
from typing import List, Set, Optional


class FailSafeGuard:
    """Circuit breaker that protects critical and local addresses from containment."""

    # Common private / local ranges that should never be blocked by default
    DEFAULT_PROTECTED_NETWORKS = [
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",          # link-local
        "fc00::/7",                # unique local IPv6
    ]

    def __init__(
        self,
        custom_whitelist: Optional[List[str]] = None,
        auto_detect_local: bool = True,
        protect_private_ranges: bool = True,
    ):
        self.whitelist: Set[str] = set()
        self.protected_networks = []

        # Explicit whitelist entries
        for entry in (custom_whitelist or []):
            self.whitelist.add(entry.strip())

        # Always protect loopback names
        self.whitelist.update(["127.0.0.1", "::1", "localhost"])

        if protect_private_ranges:
            for net in self.DEFAULT_PROTECTED_NETWORKS:
                try:
                    self.protected_networks.append(ipaddress.ip_network(net, strict=False))
                except ValueError:
                    pass

        if auto_detect_local:
            self._auto_detect()

    def _auto_detect(self) -> None:
        """Discover local interface addresses and add them to the whitelist."""
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                addr = info[4][0]
                if addr and not addr.startswith("127."):
                    self.whitelist.add(addr)
        except Exception:
            pass

        # Also try common gateway candidates via local sockets
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip:
                self.whitelist.add(local_ip)
                # Add the /24 of the local IP as a soft protect (optional, currently just the host)
        except Exception:
            pass

    def is_protected(self, ip_address: str) -> bool:
        """Return True if the IP must never be contained."""
        if ip_address in self.whitelist:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for net in self.protected_networks:
                if ip_obj in net:
                    return True
        except ValueError:
            # Invalid IP → treat as protected (safer)
            return True

        return False

    def add_immunity(self, ip_address: str) -> None:
        self.whitelist.add(ip_address)

    def remove_immunity(self, ip_address: str) -> None:
        self.whitelist.discard(ip_address)

    def verify_action_safety(self, ip_address: str) -> bool:
        """Returns True if it is safe to contain the IP."""
        if self.is_protected(ip_address):
            return False
        return True

    def get_status(self) -> dict:
        return {
            "whitelist_count": len(self.whitelist),
            "protected_networks": [str(n) for n in self.protected_networks],
            "sample_whitelist": list(self.whitelist)[:8],
        }
