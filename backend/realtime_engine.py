"""
ForensicLogX — Real-Time Analysis Engine
Receives individual log lines, parses them instantly,
runs sliding-window threat detection, keeps live counters.
"""

import re
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from backend.config import Config

LOG_RE = re.compile(
    r'(?:(?P<vhost>\S+)\s+)?'
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)
TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(raw: str):
    raw = raw.strip()
    if not raw:
        return None
    m = LOG_RE.match(raw)
    if not m:
        return None
    d = m.groupdict()
    try:
        ts = datetime.strptime(d["time"], TIME_FMT)
    except ValueError:
        ts = datetime.now()
    try:
        status = int(d["status"])
    except ValueError:
        status = 0
    try:
        byte_count = int(d["bytes"]) if d["bytes"] != "-" else 0
    except ValueError:
        byte_count = 0
    return {
        "ip":         d["ip"],
        "method":     d.get("method", "-"),
        "url":        d.get("url", "-"),
        "status":     status,
        "bytes":      byte_count,
        "user_agent": d.get("agent") or "-",
        "timestamp":  ts.strftime("%Y-%m-%d %H:%M:%S"),
        "raw":        raw,
    }


class RealtimeEngine:
    WINDOW_SECONDS = 60

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        self.logs            = deque(maxlen=5000)
        self.threats         = []
        self.threat_ids      = set()
        self.total           = 0
        self.error_count     = 0
        self.unique_ips      = set()
        self.status_counts   = defaultdict(int)
        self.method_counts   = defaultdict(int)
        self.hour_counts     = defaultdict(int)
        self._ip_times       = defaultdict(deque)
        self._ip_auth_fails  = defaultdict(deque)
        self._ip_5xx         = defaultdict(deque)
        self.blocked_ips     = set()
        self.custody         = []
        self.agent_connected = False
        self.agent_name      = "Unknown"
        self.agent_last_seen = None
        self.threat_stats    = {
            "total": 0,
            "by_type": {"SQLi": 0, "XSS": 0, "RCE": 0, "Other": 0},
            "by_ip": {},
            "by_severity": {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "NOTICE": 0}
        }
        self.modsec_threats  = deque(maxlen=50)
        self.sigma_stats     = {
            "total": 0,
            "by_level": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {},
            "by_rule": {}
        }
        self.sigma_alerts    = deque(maxlen=100)
        self._add_custody("Session started", "Real-time engine initialised", "System")

    def ingest_line(self, raw: str):
        entry = parse_line(raw)
        if not entry:
            return {"entry": None, "new_threats": []}
        with self._lock:
            self._process(entry)
            new_threats = self._detect(entry)
        return {"entry": entry, "new_threats": new_threats}

    def ingest_batch(self, lines: list):
        results = []
        for line in lines:
            results.append(self.ingest_line(line))
        return results

    def _process(self, entry):
        ip     = entry["ip"]
        status = entry["status"]
        now    = datetime.now()
        self.logs.append(entry)
        self.total += 1
        self.unique_ips.add(ip)
        self.status_counts[str(status)] += 1
        self.method_counts[entry["method"]] += 1
        self.hour_counts[now.hour] += 1
        if status >= 400:
            self.error_count += 1
        self._ip_times[ip].append(now)
        if status in (401, 403):
            self._ip_auth_fails[ip].append(now)
        if status >= 500:
            self._ip_5xx[ip].append(now)
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)
        self._prune(self._ip_times[ip], cutoff)
        self._prune(self._ip_auth_fails[ip], cutoff)
        self._prune(self._ip_5xx[ip], cutoff)

    def _detect(self, entry):
        new = []
        ip  = entry["ip"]

        # Brute Force
        af = len(self._ip_auth_fails[ip])
        if af >= Config.BRUTE_FORCE_THRESHOLD:
            t = self._make_threat(f"brute:{ip}", "Brute Force", "critical", ip,
                f"{af} auth failures in {self.WINDOW_SECONDS}s", af, entry["url"])
            if t: new.append(t)

        # HTTP Flood
        rr = len(self._ip_times[ip])
        if rr >= Config.FLOOD_THRESHOLD:
            t = self._make_threat(f"flood:{ip}", "HTTP Flood / DDoS", "critical", ip,
                f"{rr} req/{self.WINDOW_SECONDS}s — possible DDoS", rr, entry["url"])
            if t: new.append(t)

        # Directory Traversal
        if any(p in entry["url"] for p in Config.TRAVERSAL_PATTERNS):
            t = self._make_threat(f"trav:{ip}:{entry['url']}", "Directory Traversal", "high", ip,
                f"Traversal attempt: {entry['url']}", 1, entry["url"])
            if t: new.append(t)

        # Scanner
        agent   = entry.get("user_agent", "")
        matched = next((s for s in Config.SCANNER_AGENTS if s.lower() in agent.lower()), None)
        if matched:
            t = self._make_threat(f"scan:{ip}:{matched}", "Vulnerability Scanner", "high", ip,
                f"Scanner: {matched}", 1, entry["url"])
            if t: new.append(t)

        # Error Storm
        total_5xx = sum(len(v) for v in self._ip_5xx.values())
        if total_5xx >= Config.ERROR_STORM_THRESHOLD:
            key = f"err_storm:{datetime.now().strftime('%H%M')}"
            t = self._make_threat(key, "Error Storm", "medium", "Multiple",
                f"{total_5xx} server errors (5xx) in last {self.WINDOW_SECONDS}s",
                total_5xx, entry["url"])
            if t: new.append(t)

        return new

    def _make_threat(self, uid, type_, severity, ip, detail, count, url):
        if uid in self.threat_ids:
            return None
        self.threat_ids.add(uid)
        t = {"id": uid, "type": type_, "severity": severity, "ip": ip,
             "detail": detail, "count": count, "url": url,
             "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        self.threats.append(t)
        self._add_custody(f"THREAT: {type_}", f"{ip} — {detail}", "System")
        return t

    @staticmethod
    def _prune(dq, cutoff):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _top_ips(self):
        counts = defaultdict(int)
        for e in self.logs:
            counts[e["ip"]] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10])

    def get_snapshot(self):
        with self._lock:
            return {
                "total":           self.total,
                "unique_ips":      len(self.unique_ips),
                "error_count":     self.error_count,
                "error_rate":      round(self.error_count / max(self.total, 1) * 100, 1),
                "threat_count":    len(self.threats),
                "status_dist":     dict(self.status_counts),
                "method_dist":     dict(self.method_counts),
                "hour_dist":       dict(self.hour_counts),
                "top_ips":         self._top_ips(),
                "threats":         list(self.threats[-50:]),
                "recent_logs":     list(self.logs)[-100:],
                "blocked_ips":     list(self.blocked_ips),
                "custody":         list(self.custody),
                "agent_connected": self.agent_connected,
                "agent_name":      self.agent_name,
                "agent_last_seen": self.agent_last_seen,
                "modsec_threats":  list(self.modsec_threats),
                "threat_stats":    self.threat_stats,
                "sigma_stats":     self.sigma_stats,
                "sigma_alerts":    list(self.sigma_alerts),
            }

    def block_ip(self, ip, actor="Analyst"):
        with self._lock:
            self.blocked_ips.add(ip)
            self._add_custody(f"IP Blocked: {ip}", f"iptables -A INPUT -s {ip} -j DROP", actor)

    def mark_agent_connected(self, name):
        with self._lock:
            self.agent_connected = True
            self.agent_name      = name
            self.agent_last_seen = datetime.now().isoformat()
            self._add_custody("Agent Connected", f"'{name}' started streaming", "System")

    def mark_agent_disconnected(self):
        with self._lock:
            self.agent_connected = False
            self._add_custody("Agent Disconnected", "Log stream stopped", "System")

    def _add_custody(self, action, detail, actor):
        self.custody.append({
            "timestamp": datetime.now().isoformat(),
            "action": action, "detail": detail, "actor": actor,
        })

    def update_threat_stats(self, attack_type, ip, severity):
        with self._lock:
            self.threat_stats["total"] += 1
            
            # Map attack type to stats keys
            type_key = "Other"
            if attack_type == "SQL Injection":
                type_key = "SQLi"
            elif attack_type == "XSS":
                type_key = "XSS"
            elif attack_type == "RCE":
                type_key = "RCE"
            
            # Increment by_type
            self.threat_stats["by_type"][type_key] = self.threat_stats["by_type"].get(type_key, 0) + 1
            
            # Increment by_ip
            self.threat_stats["by_ip"][ip] = self.threat_stats["by_ip"].get(ip, 0) + 1
            
            # Increment by_severity
            sev_key = severity.upper()
            self.threat_stats["by_severity"][sev_key] = self.threat_stats["by_severity"].get(sev_key, 0) + 1

    def add_threat_event(self, t):
        with self._lock:
            if t["id"] not in self.threat_ids:
                self.threat_ids.add(t["id"])
                self.threats.append(t)
                self._add_custody(f"THREAT: {t['type']}", f"{t['ip']} — {t['detail']}", "System")
        self.update_threat_stats(t["type"], t["ip"], t["severity"])

    def add_modsec_threat(self, threat_rich):
        with self._lock:
            uid = f"modsec:{threat_rich['rule_id']}:{threat_rich['attacker_ip']}:{threat_rich['timestamp'][-8:]}"
            t_std = None
            if uid not in self.threat_ids:
                self.threat_ids.add(uid)
                t_std = {
                    "id": uid,
                    "type": threat_rich.get("attack_type", "Other"),
                    "severity": threat_rich["severity"].lower(),
                    "ip": threat_rich["attacker_ip"],
                    "detail": f"Blocked by ModSecurity: {threat_rich['message']}",
                    "count": 1,
                    "url": "",
                    "timestamp": threat_rich["timestamp"]
                }
                self.threats.append(t_std)
                self._add_custody(f"WAF ALERT: {threat_rich.get('attack_type', 'Other')}", f"{threat_rich['attacker_ip']} — {threat_rich['message']}", "System")
            
            self.modsec_threats.append(threat_rich)
            return t_std

    def update_sigma_stats(self, hit):
        """
        Increments Sigma metrics when a rule triggers.
        """
        with self._lock:
            self.sigma_stats["total"] += 1
            
            # Severity mapping (normalize to lower case)
            level = str(hit.get("level", "low")).lower()
            if level in self.sigma_stats["by_level"]:
                self.sigma_stats["by_level"][level] += 1
            else:
                self.sigma_stats["by_level"]["low"] += 1
                
            # Category stats
            cat = str(hit.get("category", "webserver")).lower()
            self.sigma_stats["by_category"][cat] = self.sigma_stats["by_category"].get(cat, 0) + 1
            
            # Per-rule hit counts
            rule_title = hit.get("title", "Unknown Rule")
            self.sigma_stats["by_rule"][rule_title] = self.sigma_stats["by_rule"].get(rule_title, 0) + 1
            
            # Store alert in deque
            self.sigma_alerts.append(hit)


