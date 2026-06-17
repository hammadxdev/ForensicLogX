"""
ForensicLogX — IP Blocking Module
Generates and optionally applies iptables/ufw firewall rules
to block detected malicious IPs.
"""

import subprocess
import platform
import os
from datetime import datetime


def generate_rules(ips: list[str]) -> dict:
    """
    Generate iptables and ufw firewall rules for a list of IPs.
    Returns dict with rule strings.
    """
    iptables_rules = []
    ufw_rules = []

    for ip in ips:
        iptables_rules.append(f"iptables -A INPUT -s {ip} -j DROP")
        ufw_rules.append(f"ufw deny from {ip} to any")

    save_cmd = "iptables-save > /etc/iptables/rules.v4  # Persist rules across reboots"

    return {
        "ips":            ips,
        "iptables_rules": iptables_rules,
        "ufw_rules":      ufw_rules,
        "save_command":   save_cmd,
        "script":         _generate_bash_script(ips),
        "generated_at":   datetime.now().isoformat(),
    }


def _generate_bash_script(ips: list[str]) -> str:
    """Generate a ready-to-run bash script for blocking."""
    lines = [
        "#!/bin/bash",
        "# ForensicLogX — Auto-generated IP block script",
        f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "# Run as root: sudo bash block_ips.sh",
        "",
        "echo '[ForensicLogX] Applying firewall rules...'",
        "",
    ]
    for ip in ips:
        lines.append(f"# Block {ip}")
        lines.append(f"iptables -A INPUT -s {ip} -j DROP")
        lines.append(f"ufw deny from {ip} to any")
        lines.append("")
    lines += [
        "iptables-save > /etc/iptables/rules.v4",
        "echo '[ForensicLogX] Done. All IPs blocked.'",
    ]
    return "\n".join(lines)


def apply_rules(ips: list[str], dry_run: bool = True) -> dict:
    """
    Apply firewall rules using iptables.
    dry_run=True just returns commands without executing.
    Returns result dict with success/fail per IP.
    """
    results = []
    is_linux = platform.system() == "Linux"
    is_root  = os.geteuid() == 0 if is_linux else False

    for ip in ips:
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        if dry_run or not is_linux or not is_root:
            results.append({"ip": ip, "status": "dry_run", "command": " ".join(cmd)})
        else:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)
                results.append({"ip": ip, "status": "blocked", "command": " ".join(cmd)})
            except subprocess.CalledProcessError as e:
                results.append({"ip": ip, "status": "failed", "error": str(e)})
            except Exception as e:
                results.append({"ip": ip, "status": "error", "error": str(e)})

    return {
        "dry_run": dry_run,
        "results": results,
        "blocked_count": sum(1 for r in results if r["status"] == "blocked"),
        "timestamp": datetime.now().isoformat(),
    }
