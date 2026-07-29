import subprocess

class ContainmentEngine:
    """Active isolation engine for enforcing real-time socket severance and packet dropping."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.isolated_ips = set()

    def isolate_ip(self, ip_address: str) -> bool:
        if ip_address in self.isolated_ips:
            return True

        if self.dry_run:
            print(f"[CONTAINMENT-DRY-RUN] [!] Simulating firewall DROP rule for target: {ip_address}")
            self.isolated_ips.add(ip_address)
            return True

        try:
            # Enforce iptables drop rule
            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"[CONTAINMENT] [+] Successfully isolated IP via iptables: {ip_address}")
                self.isolated_ips.add(ip_address)
                return True
            else:
                print(f"[CONTAINMENT] [!] Firewall rule execution failed: {res.stderr.strip()}")
                return False
        except Exception as e:
            print(f"[CONTAINMENT] [!] Error applying containment: {e}")
            return False

    def release_ip(self, ip_address: str) -> bool:
        if ip_address not in self.isolated_ips:
            return True

        if self.dry_run:
            print(f"[CONTAINMENT-DRY-RUN] [*] Simulating firewall UNBLOCK for target: {ip_address}")
            self.isolated_ips.remove(ip_address)
            return True

        try:
            cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True, text=True)
            self.isolated_ips.remove(ip_address)
            return True
        except Exception as e:
            print(f"[CONTAINMENT] [!] Error releasing IP: {e}")
            return False
