class FailSafeGuard:
    """Circuit breaker preventing accidental isolation of critical client infrastructure."""

    def __init__(self, custom_whitelist: list = None):
        # Default immunity list (Loopback, standard local gateways)
        self.whitelist = set(custom_whitelist or ["127.0.0.1", "localhost", "192.168.1.1"])

    def is_protected(self, ip_address: str) -> bool:
        return ip_address in self.whitelist

    def add_immunity(self, ip_address: str):
        self.whitelist.add(ip_address)

    def verify_action_safety(self, ip_address: str) -> bool:
        """Returns True if safe to execute containment; False if protected."""
        if self.is_protected(ip_address):
            print(f"[FAILSAFE] [!] Immunity active for protected IP: {ip_address}. Containment aborted.")
            return False
        return True
