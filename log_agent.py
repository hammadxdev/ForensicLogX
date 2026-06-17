#!/usr/bin/env python3
"""
ForensicLogX — Standalone Real-Time DVWA Log Streaming Agent
============================================================
Tails /var/log/apache2/vulnlab_access.log and vulnlab_error.log simultaneously
and streams new log lines to the ForensicLogX backend server.

Usage:
    sudo python3 log_agent.py <server-ip>
"""

import os
import sys
import time
import json
import socket
import threading
import urllib.request
import urllib.error

# ─── Config & Paths ──────────────────────────────────────────────────────────
PORT = 5000
LOG_FILES = {}

def detect_log_files():
    global LOG_FILES
    # Check for CLI arguments first
    custom_access = None
    custom_error = None
    
    if "--access" in sys.argv:
        try:
            custom_access = sys.argv[sys.argv.index("--access") + 1]
        except IndexError:
            pass
    if "--error" in sys.argv:
        try:
            custom_error = sys.argv[sys.argv.index("--error") + 1]
        except IndexError:
            pass
            
    # If user provided overrides, use them
    if custom_access or custom_error:
        if custom_access:
            LOG_FILES[custom_access] = "vulnlab_access"
        if custom_error:
            LOG_FILES[custom_error] = "vulnlab_error"
        return

    # Automatically scan the entire /var/log/apache2 directory
    log_dir = "/var/log/apache2"
    if os.path.exists(log_dir):
        try:
            for filename in os.listdir(log_dir):
                filepath = os.path.join(log_dir, filename)
                if os.path.isfile(filepath):
                    # Only target active files, not rotated files like access.log.1, error.log.2.gz, etc.
                    if filename.endswith("access.log"):
                        LOG_FILES[filepath] = "vulnlab_access"
                    elif filename.endswith("error.log"):
                        LOG_FILES[filepath] = "vulnlab_error"
        except Exception as e:
            print(RED(f"[AGENT] Error scanning directory {log_dir}: {e}"))
            
    # Fallback default values if directory scanning found nothing
    if not LOG_FILES:
        LOG_FILES["/var/log/apache2/access.log"] = "vulnlab_access"
        LOG_FILES["/var/log/apache2/error.log"] = "vulnlab_error"

# ─── Colors ──────────────────────────────────────────────────────────────────
def _c(code, t): return f"\033[{code}m{t}\033[0m"
RED    = lambda t: _c(31, t)
GREEN  = lambda t: _c(32, t)
YELLOW = lambda t: _c(33, t)
CYAN   = lambda t: _c(36, t)
BOLD   = lambda t: _c(1,  t)
GRAY   = lambda t: _c(90, t)

running = True

def send_log_with_retry(server_ip: str, payload: dict) -> None:
    """Send a log line to the backend with automatic retry and error handling."""
    url = f"http://{server_ip}:{PORT}/api/logs/ingest"
    body = json.dumps(payload).encode('utf-8')
    
    while running:
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 201):
                    print(GREEN(f"[AGENT] Successfully forwarded log line ({payload['log_type']})"))
                    return
        except (urllib.error.URLError, socket.timeout, ConnectionRefusedError) as e:
            print(YELLOW(f"[WARN] Connection to {url} failed: {e}. Retrying in 5 seconds..."))
            time.sleep(5)
        except Exception as e:
            print(RED(f"[ERROR] Unexpected error sending log: {e}. Retrying in 5 seconds..."))
            time.sleep(5)


def tail_log_file(filepath: str, log_type: str, server_ip: str) -> None:
    """Tails a single log file from the end and streams new lines to the server."""
    print(GREEN(f"[AGENT] Tailing thread active for: {filepath} ({log_type})"))
    f = None
    
    # Wait for the log file to appear if it doesn't exist
    while running and not os.path.exists(filepath):
        print(YELLOW(f"[AGENT] Log file {filepath} not found. Waiting for it to appear..."))
        time.sleep(5)

    try:
        f = open(filepath, "r", encoding="utf-8", errors="replace")
        f.seek(0, 2)  # Seek to the end of the file (skip existing logs)
        ino = os.stat(filepath).st_ino
    except Exception as e:
        print(RED(f"[AGENT] Failed to open {filepath}: {e}"))
        return

    while running:
        # Handle log rotation
        try:
            current_stat = os.stat(filepath)
            if current_stat.st_ino != ino:
                print(YELLOW(f"[AGENT] Log rotation detected for {filepath} — reopening file"))
                f.close()
                f = open(filepath, "r", encoding="utf-8", errors="replace")
                ino = current_stat.st_ino
        except Exception:
            pass

        try:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
                
            line_stripped = line.strip()
            if not line_stripped:
                continue

            payload = {
                "raw_log": line_stripped,
                "log_type": log_type,
                "source": os.path.basename(filepath)
            }
            
            # Send log asynchronously
            t = threading.Thread(target=send_log_with_retry, args=(server_ip, payload), daemon=True)
            t.start()
        except Exception as e:
            print(RED(f"[AGENT] Error reading {filepath}: {e}"))
            time.sleep(1)

    if f:
        f.close()


def connect_to_server(server_ip: str) -> None:
    """Signals connection startup to the central analyzer backend."""
    url = f"http://{server_ip}:{PORT}/api/agent/connect"
    payload = {"agent_name": "DVWA-LogAgent"}
    body = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(GREEN(f"[AGENT] Registered as ONLINE with backend server (Status {resp.status})"))
    except Exception as e:
        print(YELLOW(f"[WARN] Failed to send online signal to {url}: {e}. Agent will continue tailing."))


def main():
    global running
    
    # Simple CLI argument parsing
    server_ip = None
    args = sys.argv[1:]
    
    # Look for IP (first argument that doesn't follow a flag like --access or --error, and doesn't start with -)
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg in ["--access", "--error"]:
            skip = True
            continue
        if not arg.startswith("-"):
            server_ip = arg
            break

    if not server_ip:
        print(BOLD("=" * 60))
        print(BOLD("  ForensicLogX — Standalone Real-Time Log Agent"))
        print(BOLD("=" * 60))
        print(RED("  Error: Missing Server IP command-line argument."))
        print("\n  Usage:")
        print(CYAN("    sudo python3 log_agent.py <server-ip> [options]"))
        print("\n  Options:")
        print(CYAN("    --access <path>   Path to Apache access log (auto-detected by default)"))
        print(CYAN("    --error <path>    Path to Apache error log (auto-detected by default)"))
        print("\n  Example:")
        print(CYAN("    sudo python3 log_agent.py 192.168.0.105"))
        print(CYAN("    sudo python3 log_agent.py 192.168.0.105 --access /var/log/apache2/access.log"))
        print(BOLD("=" * 60))
        sys.exit(1)

    detect_log_files()

    print(BOLD("=" * 60))
    print(BOLD("  Starting Real-Time Log Streaming Agent..."))
    print(f"  Target Server IP : {server_ip}")
    for filepath, log_type in LOG_FILES.items():
        print(f"  Tailing Log File : {filepath} ({log_type})")
    print(BOLD("=" * 60))

    # Signal connection to turn the backend dashboard green
    connect_to_server(server_ip)

    threads = []
    for filepath, log_type in LOG_FILES.items():
        t = threading.Thread(
            target=tail_log_file,
            args=(filepath, log_type, server_ip),
            daemon=True
        )
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        print(YELLOW("\n[AGENT] Shutting down agent gracefully..."))
        running = False


if __name__ == "__main__":
    main()
