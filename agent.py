#!/usr/bin/env python3
"""
ForensicLogX — Multi-Source Log Streaming Agent
===============================================
Tails configured web server, WAF, and system log files in real-time,
normalizes logs, buffers them in an offline queue if the analyzer is down,
and forwards them securely to the central ForensicLogX analyzer API.

Also supports heartbeat system metrics and simulator/demo mode.
"""

import os
import sys
import time
import json
import re
import socket
import signal
import threading
import argparse
import urllib.request
import urllib.error
from datetime import datetime

# ─── Colors ──────────────────────────────────────────────────────────────────
def _c(code, t): return f"\033[{code}m{t}\033[0m"
RED    = lambda t: _c(31, t)
GREEN  = lambda t: _c(32, t)
YELLOW = lambda t: _c(33, t)
CYAN   = lambda t: _c(36, t)
BOLD   = lambda t: _c(1,  t)
GRAY   = lambda t: _c(90, t)

# ─── SQLite Queue & Registry ──────────────────────────────────────────────────
class SQLiteQueue:
    """
    Local SQLite database queue for event buffering during offline periods
    and offset registry for tracking file read states across restarts.
    """
    def __init__(self, db_path="agent_queue.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        import sqlite3
        with self.lock, sqlite3.connect(self.db_path) as conn:
            # Event queue table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT,
                    hostname TEXT,
                    log_source TEXT,
                    timestamp TEXT,
                    raw_log TEXT
                )
            """)
            # File offset tracking registry
            conn.execute("""
                CREATE TABLE IF NOT EXISTS registry (
                    filepath TEXT PRIMARY KEY,
                    inode INTEGER,
                    offset INTEGER
                )
            """)
            conn.commit()

    def put(self, agent_id, hostname, log_source, timestamp, raw_log):
        import sqlite3
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO queue (agent_id, hostname, log_source, timestamp, raw_log) VALUES (?, ?, ?, ?, ?)",
                (agent_id, hostname, log_source, timestamp, raw_log)
            )
            conn.commit()

    def get_batch(self, batch_size=50):
        import sqlite3
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT id, agent_id, hostname, log_source, timestamp, raw_log FROM queue ORDER BY id ASC LIMIT ?",
                    (batch_size,)
                )
                return cursor.fetchall()
        except sqlite3.OperationalError:
            return []

    def remove_batch(self, ids):
        import sqlite3
        if not ids:
            return
        with self.lock, sqlite3.connect(self.db_path) as conn:
            placeholder = ",".join("?" for _ in ids)
            conn.execute(f"DELETE FROM queue WHERE id IN ({placeholder})", ids)
            conn.commit()

    def size(self):
        import sqlite3
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                return conn.execute("SELECT COUNT(*) FROM queue").fetchone()[0]
        except sqlite3.OperationalError:
            return 0

    def get_offset(self, filepath):
        import sqlite3
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                row = conn.execute("SELECT inode, offset FROM registry WHERE filepath = ?", (filepath,)).fetchone()
                return row if row else (None, None)
        except sqlite3.OperationalError:
            return (None, None)

    def save_offset(self, filepath, inode, offset):
        import sqlite3
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO registry (filepath, inode, offset) VALUES (?, ?, ?)",
                (filepath, inode, offset)
            )
            conn.commit()


# ─── Forwarder Agent ──────────────────────────────────────────────────────────
class WebAnalyzerAgent:
    def __init__(self, config_path="agent_conf"):
        self.config_path = config_path
        self.running = True
        self.hostname = socket.gethostname()
        self.threads = []
        self.queue = SQLiteQueue()
        
        # Default configuration values
        self.server_url = "http://127.0.0.1:5000"
        self.api_key = "FLX-DEMO-TOKEN-2026"
        self.agent_id = f"ubuntu-dvwa-agent-01"
        self.heartbeat_interval = 60
        self.flush_interval = 5
        
        # Log paths to monitor
        self.log_sources = {}
        
        self.load_config()

    def load_config(self):
        # Allow reading config file from agent.conf or agent_conf
        path = self.config_path
        if not os.path.exists(path) and os.path.exists("agent.conf"):
            path = "agent.conf"
            
        if not os.path.exists(path):
            print(YELLOW(f"[AGENT] Configuration file not found at {path}. Using defaults."))
            # Setup default test paths
            self.log_sources = {
                "/var/log/apache2/access.log": "apache_access",
                "/var/log/apache2/error.log": "apache_error",
                "/var/log/modsec_audit.log": "modsec_audit",
                "/var/log/auth.log": "auth_log",
                "/var/log/syslog": "syslog"
            }
            return

        print(GREEN(f"[AGENT] Loading configuration from {path}"))
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("["):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip()
                        if not v:
                            continue
                        if k == "server_url":
                            self.server_url = v
                        elif k == "api_key":
                            self.api_key = v
                        elif k == "agent_id":
                            self.agent_id = v
                        elif k == "heartbeat_interval":
                            self.heartbeat_interval = int(v)
                        elif k == "flush_interval":
                            self.flush_interval = int(v)
                        else:
                            # Log sources paths
                            self.log_sources[v] = k
        except Exception as e:
            print(RED(f"[AGENT] Failed to read configuration: {e}"))

    def get_cpu_usage(self):
        try:
            with open('/proc/stat', 'r') as f:
                line1 = f.readline().strip().split()[1:]
            time.sleep(0.2)
            with open('/proc/stat', 'r') as f:
                line2 = f.readline().strip().split()[1:]
            
            work1 = sum(float(x) for x in line1[:3])
            total1 = sum(float(x) for x in line1)
            work2 = sum(float(x) for x in line2[:3])
            total2 = sum(float(x) for x in line2)
            
            diff_work = work2 - work1
            diff_total = total2 - total1
            if diff_total == 0:
                return "0.0%"
            return f"{round((diff_work / diff_total) * 100, 1)}%"
        except Exception:
            return "0.0%"

    def get_mem_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
            mem_total = 0
            mem_free = 0
            mem_buffers = 0
            mem_cached = 0
            for line in lines:
                if 'MemTotal' in line:
                    mem_total = int(line.split()[1])
                elif 'MemFree' in line:
                    mem_free = int(line.split()[1])
                elif 'Buffers' in line:
                    mem_buffers = int(line.split()[1])
                elif 'Cached' in line:
                    mem_cached = int(line.split()[1])
            used = mem_total - mem_free - mem_buffers - mem_cached
            if mem_total == 0:
                return "0.0%"
            return f"{round((used / mem_total) * 100, 1)}%"
        except Exception:
            return "0.0%"

    def get_disk_usage(self):
        try:
            stat = os.statvfs('/')
            total = stat.f_blocks * stat.f_frsize
            free = stat.f_bfree * stat.f_frsize
            used = total - free
            if total == 0:
                return "0.0%"
            return f"{round((used / total) * 100, 1)}%"
        except Exception:
            return "0.0%"

    def tail_worker(self, filepath, log_source):
        print(GREEN(f"[AGENT] Started tailing thread for {filepath} ({log_source})"))
        f = None
        ino = None
        
        # Initial open attempt
        try:
            if os.path.exists(filepath):
                ino = os.stat(filepath).st_ino
                f = open(filepath, "r", encoding="utf-8", errors="replace")
                saved_ino, saved_offset = self.queue.get_offset(filepath)
                if saved_ino == ino:
                    f.seek(saved_offset)
                    print(GRAY(f"        Resumed {filepath} from offset {saved_offset}"))
                else:
                    f.seek(0, 2)  # seek to end
                    self.queue.save_offset(filepath, ino, f.tell())
        except Exception as e:
            print(YELLOW(f"[AGENT] Cannot open {filepath} initially: {e}"))
            f = None

        modsec_buffer = []
        in_modsec = False
        modsec_boundary = None

        while self.running:
            if not f:
                if os.path.exists(filepath):
                    try:
                        ino = os.stat(filepath).st_ino
                        f = open(filepath, "r", encoding="utf-8", errors="replace")
                        f.seek(0, 2)
                        self.queue.save_offset(filepath, ino, f.tell())
                        print(GREEN(f"[AGENT] File appeared: tailing {filepath}"))
                    except Exception:
                        pass
                if not f:
                    time.sleep(2)
                    continue

            # Check for log rotation
            try:
                current_stat = os.stat(filepath)
                if current_stat.st_ino != ino:
                    print(YELLOW(f"[AGENT] Log rotation detected for {filepath} — reopening file"))
                    f.close()
                    ino = current_stat.st_ino
                    f = open(filepath, "r", encoding="utf-8", errors="replace")
                    f.seek(0)
                    self.queue.save_offset(filepath, ino, 0)
            except Exception:
                pass

            # Read lines
            try:
                line = f.readline()
                if not line:
                    self.queue.save_offset(filepath, ino, f.tell())
                    time.sleep(0.5)
                    continue

                line_raw = line
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                # Group ModSecurity multiline blocks
                if log_source == "modsec_audit":
                    start_match = re.match(r'^--([a-fA-F0-9]+)-A--$', line_stripped)
                    if start_match:
                        in_modsec = True
                        modsec_boundary = start_match.group(1)
                        modsec_buffer = [line_stripped]
                    elif in_modsec:
                        modsec_buffer.append(line_stripped)
                        if line_stripped == f"--{modsec_boundary}-Z--":
                            raw_txn = "\n".join(modsec_buffer)
                            self.queue.put(self.agent_id, self.hostname, log_source, "auto", raw_txn)
                            in_modsec = False
                            modsec_boundary = None
                            modsec_buffer = []
                else:
                    self.queue.put(self.agent_id, self.hostname, log_source, "auto", line_stripped)
            except Exception as e:
                time.sleep(2)

        if f:
            f.close()

    def sender_loop(self):
        print(GREEN("[AGENT] Sender pipeline thread active."))
        while self.running:
            size = self.queue.size()
            if size == 0:
                time.sleep(self.flush_interval)
                continue

            batch = self.queue.get_batch(batch_size=30)
            if not batch:
                time.sleep(self.flush_interval)
                continue

            payload = []
            for item in batch:
                payload.append({
                    "agent_id": item[1],
                    "hostname": item[2],
                    "log_source": item[3],
                    "timestamp": item[4],
                    "raw_log": item[5]
                })

            url = f"{self.server_url}/api/agent/logs"
            try:
                body = json.dumps(payload).encode()
                req = urllib.request.Request(
                    url, data=body,
                    headers={"Content-Type": "application/json", "X-API-Key": self.api_key}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    res = json.loads(resp.read().decode())
                    if res.get("status") == "success":
                        ids = [item[0] for item in batch]
                        self.queue.remove_batch(ids)
                    else:
                        time.sleep(5)
            except Exception as e:
                time.sleep(5)

    def heartbeat_loop(self):
        print(GREEN("[AGENT] Heartbeat reporter thread active."))
        while self.running:
            cpu = self.get_cpu_usage()
            mem = self.get_mem_usage()
            disk = self.get_disk_usage()
            
            payload = {
                "agent_status": "online",
                "hostname": self.hostname,
                "os": "Ubuntu Server (Linux)",
                "cpu_usage": cpu,
                "memory_usage": mem,
                "disk_usage": disk,
                "last_seen": datetime.utcnow().isoformat() + "Z"
            }
            
            url = f"{self.server_url}/api/agent/heartbeat"
            try:
                body = json.dumps(payload).encode()
                req = urllib.request.Request(
                    url, data=body,
                    headers={"Content-Type": "application/json", "X-API-Key": self.api_key}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    pass
            except Exception:
                pass
                
            time.sleep(self.heartbeat_interval)

    def start(self):
        print(BOLD("=" * 60))
        print(BOLD("  ForensicLogX — Real-Time Log Forwarder Agent"))
        print(BOLD("  BS Digital Forensics & Cyber Security"))
        print(BOLD("=" * 60))
        print(f"  Server URL : {self.server_url}")
        print(f"  Hostname   : {self.hostname}")
        print(f"  Agent ID   : {self.agent_id}")
        print(f"  Sources    : {len(self.log_sources)} paths configured")
        print(BOLD("=" * 60))

        # Start sender and heartbeat threads
        t_send = threading.Thread(target=self.sender_loop, daemon=True)
        t_send.start()
        self.threads.append(t_send)

        t_heart = threading.Thread(target=self.heartbeat_loop, daemon=True)
        t_heart.start()
        self.threads.append(t_heart)

        # Start tailer workers
        for filepath, log_source in self.log_sources.items():
            t_tail = threading.Thread(target=self.tail_worker, args=(filepath, log_source), daemon=True)
            t_tail.start()
            self.threads.append(t_tail)

        # Main thread wait loop
        while self.running:
            try:
                time.sleep(1)
            except (KeyboardInterrupt, SystemExit):
                self.stop()
                break

    def stop(self):
        print(YELLOW("\n[AGENT] Shutting down agent threads..."))
        self.running = False


# ─── Attack Simulator Mode ───────────────────────────────────────────────────
class AttackSimulator:
    NORMAL_IPS  = ["192.168.1.101","192.168.1.102","10.0.0.5","10.0.0.6","10.0.0.7"]
    NORMAL_URLS = ["/","/index.html","/about","/contact","/products",
                   "/blog","/api/data","/dashboard","/shop","/faq"]
    AGENTS      = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]

    def __init__(self, speed=1.0):
        self.speed = speed
        self.start = datetime.now()

    def _elapsed(self):
        return (datetime.now() - self.start).total_seconds() / self.speed

    def _ts(self):
        return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0500")

    def _normal_line(self):
        ip  = socket.gethostbyname(socket.gethostname()) if random_pct(10) else "192.168.1.101"
        url = "/" if random_pct(50) else "/index.php"
        return f'{ip} - - [{self._ts()}] "GET {url} HTTP/1.1" 200 4502 "-" "Mozilla/5.0"'

    def generate_attack(self, phase):
        ts = self._ts()
        ip = "185.220.101.34"
        if phase == "brute":
            return f'{ip} - - [{ts}] "POST /login.php HTTP/1.1" 401 1200 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "cmd":
            return f'{ip} - - [{ts}] "POST /vulnerabilities/exec/ HTTP/1.1" 200 850 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "csrf":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/csrf/?password_new=password&password_conf=password&Change=Change HTTP/1.1" 200 420 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "traversal":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/fi/?page=../../../../etc/passwd HTTP/1.1" 200 950 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "upload":
            return f'{ip} - - [{ts}] "POST /vulnerabilities/upload/ HTTP/1.1" 200 350 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "captcha":
            return f'{ip} - - [{ts}] "POST /vulnerabilities/captcha/ HTTP/1.1" 200 510 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "sqli":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/sqli/?id=1%27+UNION+SELECT+null%2Cusername+FROM+users%23&Submit=Submit HTTP/1.1" 200 450 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "sqli_blind":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/sqli_blind/?id=1%27+AND+1%3DAND+sleep(5)%23&Submit=Submit HTTP/1.1" 200 480 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "weak_id":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/weak_id/ HTTP/1.1" 200 320 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "xss_dom":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/xss_d/?default=English%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 680 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "xss_reflected":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/xss_r/?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1" 200 612 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "xss_stored":
            return f'{ip} - - [{ts}] "POST /vulnerabilities/xss_s/ HTTP/1.1" 200 410 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "csp":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/csp/?callback=jsonp HTTP/1.1" 200 300 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "javascript":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/javascript/?phrase=__proto__ HTTP/1.1" 200 340 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "auth_bypass":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/auth_bypass/?user_token=bypass HTTP/1.1" 200 290 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "redirect":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/redirect/?url=http://evil.com HTTP/1.1" 200 310 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "crypto":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/crypto/?md5=098f6bcd4621d373cade4e832627b4f6 HTTP/1.1" 200 330 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "api":
            return f'{ip} - - [{ts}] "GET /vulnerabilities/api/users HTTP/1.1" 200 360 "-" "Mozilla/5.0"', "apache_access"
        elif phase == "scanner":
            return f'{ip} - - [{ts}] "GET / HTTP/1.1" 404 120 "-" "Nikto/2.1.6"', "apache_access"
        else:
            return self._normal_line(), "apache_access"

def random_pct(pct):
    import random
    return random.random() * 100 < pct

def run_simulator(server, speed):
    print(BOLD("=" * 60))
    print(BOLD("  ForensicLogX — Log Simulation Mode"))
    print(BOLD("=" * 60))
    print(f"  Target Server : {server}")
    print(BOLD("=" * 60))

    sim = AttackSimulator(speed)
    running = True

    # Keep registering agent heartbeat
    def send_sim_heartbeat():
        while running:
            payload = {
                "agent_status": "online",
                "hostname": "ubuntu-simulated",
                "os": "Ubuntu Server (Simulated)",
                "cpu_usage": "15.4%",
                "memory_usage": "48.2%",
                "disk_usage": "32.1%",
                "last_seen": datetime.utcnow().isoformat() + "Z"
            }
            try:
                req = urllib.request.Request(
                    f"{server}/api/agent/heartbeat",
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass
            time.sleep(15)

    threading.Thread(target=send_sim_heartbeat, daemon=True).start()

    PHASES = [
        (0, 10, "normal", "Sending Normal Traffic"),
        (10, 20, "brute", "Simulating Brute Force (POST /login.php)"),
        (20, 30, "cmd", "Simulating Command Injection (exec whoami)"),
        (30, 40, "csrf", "Simulating CSRF (Change Password Link)"),
        (40, 50, "traversal", "Simulating File Inclusion (LFI/RFI)"),
        (50, 60, "upload", "Simulating File Upload (.php shell)"),
        (60, 70, "captcha", "Simulating Insecure CAPTCHA Bypass"),
        (70, 80, "sqli", "Simulating SQL Injection (UNION SELECT)"),
        (80, 90, "sqli_blind", "Simulating SQL Injection (Blind - sleep)"),
        (90, 100, "weak_id", "Simulating Weak Session IDs / Fixation"),
        (100, 110, "xss_dom", "Simulating XSS (DOM-based default)"),
        (110, 120, "xss_reflected", "Simulating XSS (Reflected <script>)"),
        (120, 130, "xss_stored", "Simulating XSS (Stored comments)"),
        (130, 140, "csp", "Simulating CSP Bypass (JSONP callback)"),
        (140, 150, "javascript", "Simulating JavaScript Attack (__proto__)"),
        (150, 160, "auth_bypass", "Simulating Authorisation Bypass (Privilege Elevation)"),
        (160, 170, "redirect", "Simulating Open HTTP Redirect (url=http://)"),
        (170, 180, "crypto", "Simulating Cryptography (Weak MD5 hash params)"),
        (180, 190, "api", "Simulating API exploitation"),
        (190, 200, "scanner", "Simulating Vulnerability Scanner (Nikto)"),
        (200, 9999, "normal", "Simulating Normal Recovery Traffic")
    ]

    try:
        while True:
            elapsed = sim._elapsed()
            phase_type = "normal"
            desc = ""
            for start, end, p_type, description in PHASES:
                if start <= elapsed < end:
                    phase_type = p_type
                    desc = description
                    break
            
            line, source = sim.generate_attack(phase_type)
            print(f"  {GRAY(datetime.now().strftime('%H:%M:%S'))} [{CYAN(source.upper())}] {line[:100]}... ({YELLOW(desc)})")

            # Send to server
            payload = {
                "agent_id": "simulated-agent-01",
                "hostname": "ubuntu-simulated",
                "log_source": source,
                "timestamp": "auto",
                "raw_log": line
            }
            try:
                req = urllib.request.Request(
                    f"{server}/api/agent/logs",
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"}
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                print(RED(f"  Failed to send log: {e}"))

            # If ModSecurity phase, let's also simulate a ModSecurity audit block
            if phase_type in ("sqli", "sqli_blind", "xss_reflected", "xss_stored", "xss_dom", "csrf", "cmd", "traversal", "upload", "captcha", "weak_id", "csp", "javascript", "auth_bypass", "redirect", "crypto", "api") and random_pct(40):
                rule_id = 942100
                if phase_type == "sqli_blind": rule_id = 942120
                elif phase_type == "xss_reflected": rule_id = 941100
                elif phase_type == "xss_stored": rule_id = 941210
                elif phase_type == "xss_dom": rule_id = 941200
                elif phase_type == "csrf": rule_id = 950110
                elif phase_type == "cmd": rule_id = 932100
                elif phase_type == "traversal": rule_id = 930100
                elif phase_type == "upload": rule_id = 955100
                elif phase_type == "captcha": rule_id = 950120
                elif phase_type == "weak_id": rule_id = 943100
                elif phase_type == "csp": rule_id = 950130
                elif phase_type == "javascript": rule_id = 950140
                elif phase_type == "auth_bypass": rule_id = 950150
                elif phase_type == "redirect": rule_id = 950160
                elif phase_type == "crypto": rule_id = 950170
                elif phase_type == "api": rule_id = 950180
                
                # Send matching ModSec audit log
                modsec_txn = f"""
--abcdef01-A--
[{datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')}] [1234] [client 185.220.101.34:54321] ModSecurity: Warning.
--abcdef01-B--
GET /vulnerabilities/ HTTP/1.1
Host: example.com

--abcdef01-F--
HTTP/1.1 403 Forbidden
Content-Type: text/html

--abcdef01-H--
Message: Warning. Pattern match for {phase_type.upper()} attack. [id "{rule_id}"] [msg "{phase_type.upper()} Attack Blocked by WAF"] [severity "CRITICAL"]
Inbound-Anomaly-Score: 15
Engine-Mode: "BLOCK"

--abcdef01-Z--
"""
                payload_ms = {
                    "agent_id": "simulated-agent-01",
                    "hostname": "ubuntu-simulated",
                    "log_source": "modsec_audit",
                    "timestamp": "auto",
                    "raw_log": modsec_txn.strip()
                }
                try:
                    req = urllib.request.Request(
                        f"{server}/api/agent/logs",
                        data=json.dumps(payload_ms).encode(),
                        headers={"Content-Type": "application/json"}
                    )
                    urllib.request.urlopen(req, timeout=5)
                    print(f"  {GRAY(datetime.now().strftime('%H:%M:%S'))} {RED('[WAF BLOCK]')} Sent simulated ModSecurity alert (Rule {rule_id})")
                except Exception:
                    pass

            time.sleep(1.5 * speed)
    except KeyboardInterrupt:
        running = False
        print(YELLOW("\n[AGENT] Simulator stopped."))


# ─── Entry Point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="ForensicLogX Multi-Source Log Streaming Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py                             Run in standard multi-file tailing mode
  python agent.py --simulate                  Run in simulator mode for dashboard demonstration
  python agent.py --simulate --speed 0.5      Run simulator at 2x speed (half delay)
"""
    )
    parser.add_argument("--config",   default="agent.conf", help="Path to config file")
    parser.add_argument("--server",   default="http://127.0.0.1:5000", help="ForensicLogX server URL (simulator override)")
    parser.add_argument("--simulate", action="store_true",    help="Simulate attack traffic (demo mode)")
    parser.add_argument("--speed",    type=float, default=1.0,help="Simulation speed multiplier (0.5=fast)")
    args = parser.parse_args()

    if args.simulate:
        run_simulator(args.server, args.speed)
    else:
        agent = WebAnalyzerAgent(args.config)
        agent.start()

if __name__ == "__main__":
    main()
