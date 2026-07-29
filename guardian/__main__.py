import sys
import os
from .stealth import AntiTamperVault, masquerade_process
from .neural_core import NeuralCore
from .failsafe import FailSafeGuard
from .containment import ContainmentEngine
from .forensics import ForensicInvestigator
from .sniffer import PortSensor

def main():
    masquerade_process("[systemd-resolved]")
    
    vault_files = [os.path.join(os.path.dirname(__file__), "config.json"), __file__]
    vault = AntiTamperVault(vault_files)
    
    print("\n" + "="*50)
    print("      TRINTECH GUARDIAN - ACTIVE DEFENSE GRID")
    print("="*50)
    
    if not vault.verify_integrity():
        print("[!] CRITICAL: Core files tampered with! Initiating lockdown...")
        sys.exit(1)

    core = NeuralCore(alert_threshold=50)
    failsafe = FailSafeGuard()
    containment = ContainmentEngine(dry_run=True)
    forensics = ForensicInvestigator()

    print("[+] Ghost Node: ENGAGED")
    print("[+] Neural Core: ONLINE")
    print("[+] Fail-Safe Circuit: ONLINE")
    print("[+] Containment Engine: ONLINE (Dry-Run Mode)")
    print("[+] Forensic Engine: ONLINE")

    # Threat Callback
    def threat_handler(src_ip, dst_port):
        if failsafe.is_protected(src_ip):
            return

        analysis = core.record_event(src_ip, dst_port)
        
        if analysis['trigger_containment']:
            print(f"\n[!] THREAT DETECTED: {src_ip} -> Score: {analysis['score']} ({analysis['severity']})")
            
            if failsafe.verify_action_safety(src_ip):
                success = containment.isolate_ip(src_ip)
                if success:
                    action = "ISOLATED_IPTABLES_DROP" if not containment.dry_run else "DRY_RUN_LOGGED"
                    forensics.generate_snapshot(analysis, action_taken=action)
                    core.threat_scores[src_ip] = 0

    # Boot User-Space Sensor (Bypasses Termux/PRoot raw socket restrictions)
    sensor = PortSensor(callback_function=threat_handler)
    
    print("\n[*] Guardian operational. System listening... (Press Ctrl+C to exit)")
    try:
        sensor.start()
    except KeyboardInterrupt:
        print("\n[*] Guardian shutting down gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
