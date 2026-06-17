"""
ForensicLogX — CRS-Based Log Detector
======================================
Analyses Apache / Nginx access-log lines and matches them against OWASP
ModSecurity CRS patterns.  Produces structured DetectedAttack dicts and
optionally persists them to the SQLite database (dataset/crs_rules.db).

The detector works in two complementary layers:
  1. Fast hard-coded heuristics (regex patterns per attack family)
     — these run first and catch well-known payloads without
       needing every CRS rule to compile.
  2. CRS rule pattern matching — iterates the loaded rule set and
     applies the @rx / @pm operators from the parsed rules.

Usage::
    from backend.crs_detector import CRSDetector
    detector = CRSDetector()
    detector.load()                          # parse CRS rules once
    alerts = detector.analyze_line(raw_log_line)
    # alerts → list of alert dicts (may be empty for benign traffic)
"""

import re
import json
import sqlite3
import logging
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from backend.crs_parser import CRSParser, DB_PATH

logger = logging.getLogger(__name__)

# ─── Apache / Combined Log Format regex ───────────────────────────────────────
# 192.168.1.1 - - [05/May/2026:21:14:41 +0500] "GET /path HTTP/1.1" 200 1234 "ref" "ua"
APACHE_RE = re.compile(
    r'(?:(?P<vhost>\S+)\s+)?'
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# ─── Hard-coded heuristic rule patterns ───────────────────────────────────────
#
# Each entry:  (rule_id, category, severity, description, compiled_pattern)
# These run before CRS DB rules for speed and broad coverage.

_HEURISTICS: List[Tuple[int, str, str, str, re.Pattern]] = []


def _h(rid, cat, sev, desc, pattern, flags=re.IGNORECASE):
    _HEURISTICS.append((rid, cat, sev, desc, re.compile(pattern, flags)))


# ─── DVWA Vulnerability Heuristics ──────────────────────────────────────────

# 1. SQL Injection & SQL Injection (Blind)
_h(942100, "SQL Injection", "CRITICAL",
   "SQL Injection: UNION/SELECT Attack",
   r"(?:union\s+(?:all\s+)?select|select\s+.+\s+from|insert\s+into|delete\s+from|"
   r"drop\s+(?:table|database)|update\s+\w+\s+set|exec(?:ute)?\s*\(|xp_cmdshell)")

_h(942110, "SQL Injection", "CRITICAL",
   "SQL Injection: Boolean/Error-based",
   r"(?:'\s*(?:or|and)\s+['\d]|--\s*$|\bor\s+1\s*=\s*1\b|'\s*;|/\*.*?\*/|@@version)")

_h(942120, "SQL Injection (Blind)", "HIGH",
   "SQL Injection: Time-based Blind",
   r"(?:sleep\s*\(\s*\d+|benchmark\s*\(|waitfor\s+delay|pg_sleep)")

_h(942130, "SQL Injection", "HIGH",
   "SQL Injection: Tautology",
   r"(?:'\s*=\s*'|1\s*=\s*1|'\s*or\s*'\w*'\s*=\s*'\w*)")

# 2. XSS (Reflected, Stored, DOM)
_h(941100, "XSS (Reflected)", "CRITICAL",
   "XSS: Script Tag Injection",
   r"<script[\s>]|</script>|<script/")

_h(941110, "XSS (Reflected)", "CRITICAL",
   "XSS: Event Handler Injection",
   r"on(?:load|error|click|mouseover|focus|blur|change|submit|keyup|keydown|keypress)\s*=")

_h(941120, "XSS (Reflected)", "CRITICAL",
   "XSS: JavaScript URI",
   r"javascript\s*:|vbscript\s*:|data\s*:text/html")

_h(941130, "XSS (Reflected)", "HIGH",
   "XSS: HTML Attribute Injection",
   r"(?:document\.cookie|document\.write|window\.location|innerHTML\s*=|eval\s*\()")

_h(941200, "XSS (DOM)", "HIGH",
   "XSS: DOM-based Target Access",
   r"/xss_d\b|default=.*(?:script|alert|onload|onerror)")

_h(941210, "XSS (Stored)", "HIGH",
   "XSS: Stored Target Access",
   r"/xss_s\b")

# 3. File Inclusion (LFI/RFI)
_h(930100, "File Inclusion", "HIGH",
   "LFI: Path Traversal",
   r"(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|/etc/passwd|/etc/shadow|/etc/hosts)")

_h(930110, "File Inclusion", "HIGH",
   "LFI: Sensitive File Access",
   r"(?:/proc/self/|/var/log/|/boot\.ini|win\.ini|system32|\.htaccess|web\.config|wp-config\.php)")

_h(931100, "File Inclusion", "HIGH",
   "RFI: Remote File Inclusion",
   r"(?:https?://[^/\s]+/[^\s]+\.(?:php|asp|jsp|txt))")

# 4. Command Injection (RCE)
_h(932100, "Command Injection", "CRITICAL",
   "Command Injection via Shell Metacharacters",
   r"(?:;\s*(?:cat|ls|id|whoami|pwd|wget|curl|bash|sh|python|perl|ruby|nc)\b"
   r"|\|\s*(?:cat|ls|id|whoami)\b|`[^`]+`|\$\([^)]+\))")

_h(932105, "Command Injection", "CRITICAL",
   "Shell Command via Pipe/Ampersand",
   r"(?:&&|>>|<<|\|\||cmd\.exe|powershell|/bin/sh|/bin/bash)")

_h(932110, "Command Injection", "HIGH",
   "RCE: Log4Shell / JNDI Injection",
   r"\$\{(?:jndi|lower|upper|:-|\w+:)[^}]*\}")

# 5. File Upload / Web Shell
_h(955100, "File Upload", "CRITICAL",
   "Web Shell: Common Shell File Access / Upload",
   r"(?:shell\.php|cmd\.php|webshell|r57\.php|c99\.php|b374k\.php|"
   r"WSO\.php|FilesMan\.php|phpspy|minishell|alfashell|/vulnerabilities/upload)")

# 6. CSRF
_h(950110, "CSRF", "HIGH",
   "CSRF: Cross-Site Request Forgery attempt",
   r"/csrf|csrf_token|csrf")

# 7. Insecure CAPTCHA
_h(950120, "Insecure CAPTCHA", "MEDIUM",
   "Insecure CAPTCHA: CAPTCHA validation bypass attempt",
   r"/captcha|g-recaptcha|recaptcha_response")

# 8. Weak Session IDs
_h(943100, "Weak Session IDs", "MEDIUM",
   "Session: Session Fixation / Predictability attempt",
   r"(?:set-cookie\s*:.*(?:session|phpsessid|jsessionid).*=.*%3[Bb]|document\.cookie\s*=|/weak_id|dvwaSession)")

# 9. CSP Bypass
_h(950130, "CSP Bypass", "MEDIUM",
   "CSP Bypass: Content Security Policy evasion attempt",
   r"/csp|csp_bypass|jsonp\?callback=")

# 10. JavaScript Attacks
_h(950140, "JavaScript Attacks", "HIGH",
   "JavaScript Attack: Node/V8 exploitation attempt",
   r"/javascript|__proto__|prototype\s*pollution")

# 11. Authorisation Bypass
_h(950150, "Authorisation Bypass", "HIGH",
   "Authorisation Bypass: Privilege escalation attempt",
   r"/auth_bypass|/admin/|admin=true|user_token=")

# 12. Open HTTP Redirect
_h(950160, "Open HTTP Redirect", "MEDIUM",
   "Open HTTP Redirect: Redirect to untrusted site",
   r"/redirect\b|(?:url|redirect|goto|link)=https?://")

# 13. Cryptography
_h(950170, "Cryptography", "MEDIUM",
   "Cryptography: Insecure cryptographic parameter/endpoint",
   r"/crypto|md5=|sha1=|/[a-f0-9]{32}\b")

# 14. API
_h(950180, "API", "MEDIUM",
   "API: API abuse or unauthorized access attempt",
   r"/api/v[0-9]|/api/users|/api/admin")

# 15. Brute Force
_h(999100, "Brute Force", "HIGH",
   "Brute Force: Login attempts or page sweep",
   r"/login\.php|/wp-login\.php")

# 16. Scanner Detection (913xxx)
_h(913100, "Scanner", "MEDIUM",
   "Scanner: Automated Security Scanner",
   r"(?:nikto|masscan|nmap|sqlmap|dirbuster|gobuster|wfuzz|nuclei|hydra|"
   r"acunetix|nessus|openvas|burpsuite|zaproxy|zgrab|python-requests/|"
   r"go-http-client|libwww-perl|wget/|curl/)")

# 17. Protocol Violations (920xxx)
_h(920100, "Protocol", "LOW",
   "Protocol: Unusual HTTP Method",
   r'"(?:TRACE|TRACK|DEBUG|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|PATCH)\s')

_h(920200, "Protocol", "MEDIUM",
   "Protocol: HTTP Request Smuggling",
   r"(?:transfer-encoding\s*:\s*chunked.*content-length:|content-length\s*:\s*\d+.*transfer-encoding)")

# 18. PHP / Java Injections (map to Command Injection / JavaScript Attacks / SQLi depending on context)
_h(933100, "Command Injection", "HIGH",
   "PHP: PHP Code Injection",
   r"(?:<%=|<\?php|<%@|eval\s*\(|base64_decode\s*\(|preg_replace\s*\(.*\/e|"
   r"passthru|shell_exec|system\s*\(|popen\s*\(|proc_open)")

_h(944100, "Command Injection", "CRITICAL",
   "Java: Deserialization / OGNL Injection",
   r"(?:\$\{[^}]*?(?:Runtime|ProcessBuilder|exec|invoke)[^}]*\}|"
   r"ognl\.|struts\.action|%24%7B|java\.lang\.Runtime)")


# ─── Normalized Category Mapper ──────────────────────────────────────────────

def normalize_category(cat: str, url: str = "") -> str:
    cat_lower = cat.lower()
    url_lower = url.lower()
    
    if "sqli" in cat_lower or "sql injection" in cat_lower:
        if any(p in url_lower for p in ["sleep", "benchmark", "pg_sleep", "delay"]):
            return "SQL Injection (Blind)"
        return "SQL Injection"
    elif "xss" in cat_lower or "cross-site" in cat_lower:
        if "xss_d" in url_lower:
            return "XSS (DOM)"
        elif "xss_s" in url_lower:
            return "XSS (Stored)"
        else:
            return "XSS (Reflected)"
    elif cat_lower in ("lfi", "rfi", "file inclusion"):
        return "File Inclusion"
    elif cat_lower in ("rce", "command", "command injection"):
        return "Command Injection"
    elif "webshell" in cat_lower or "upload" in cat_lower:
        return "File Upload"
    elif "captcha" in cat_lower or "insecure captcha" in cat_lower:
        return "Insecure CAPTCHA"
    elif "session" in cat_lower or "fixation" in cat_lower or "weak_id" in cat_lower or "weak session" in cat_lower:
        return "Weak Session IDs"
    elif "csrf" in cat_lower:
        return "CSRF"
    elif "csp" in cat_lower:
        return "CSP Bypass"
    elif "javascript" in cat_lower or "js" in cat_lower:
        return "JavaScript Attacks"
    elif "auth_bypass" in cat_lower or "auth bypass" in cat_lower or "privilege" in cat_lower or "authorisation" in cat_lower:
        return "Authorisation Bypass"
    elif "redirect" in cat_lower:
        return "Open HTTP Redirect"
    elif "crypto" in cat_lower:
        return "Cryptography"
    elif "api" in cat_lower:
        return "API"
    elif "brute" in cat_lower:
        return "Brute Force"
    return cat


# ─── Detected Attack schema helpers ──────────────────────────────────────────

def _make_alert(
    rule_id:         int,
    category:         str,
    severity:        str,
    description:     str,
    matched_pattern: str,
    source_ip:       str,
    log_line:        str,
    method:          str = "",
    url:             str = "",
    status:          int = 0,
    user_agent:      str = "",
    blocked:         bool = False,
) -> dict:
    normalized_cat = normalize_category(category, url)
    return {
        "timestamp":       datetime.utcnow().isoformat() + "Z",
        "rule_id":         rule_id,
        "category":        normalized_cat,
        "severity":        severity,
        "description":     description,
        "matched_pattern": matched_pattern[:200],
        "source_ip":       source_ip,
        "method":          method,
        "url":             url[:500],
        "status_code":     status,
        "user_agent":      user_agent[:200],
        "log_line":        log_line[:800],
        "blocked":         blocked,
    }


# ─── CRS Detector ─────────────────────────────────────────────────────────────

class CRSDetector:
    """
    Analyses single log lines against CRS patterns and heuristics.

    Parameters
    ----------
    rules_dir : path to the CRS .conf files (default: dataset/rules/)
    db_path   : SQLite DB path (default: dataset/crs_rules.db)
    max_crs   : maximum number of CRS DB rules compiled into regex
                (set lower on slow machines; heuristics always run)
    """

    def __init__(
        self,
        rules_dir: Optional[str] = None,
        db_path:   Optional[str] = None,
        max_crs:   int = 500,
    ) -> None:
        self._parser   = CRSParser(rules_dir=rules_dir, db_path=db_path)
        self._db_path  = Path(db_path) if db_path else DB_PATH
        self._max_crs  = max_crs
        self._loaded   = False

        # Compiled CRS rules:  [(rule_id, category, severity, desc, pattern_re)]
        self._crs_patterns: List[Tuple[int, str, str, str, re.Pattern]] = []

        self._ensure_alerts_table()

    # ── Public API ────────────────────────────────────────────────────────────

    def load(self, paranoia_level: int = 2, force_reload: bool = False) -> int:
        """
        Load CRS rules from database (parses .conf files first if DB is empty).
        Returns the number of compiled CRS patterns.
        """
        if self._loaded and not force_reload:
            return len(self._crs_patterns)

        # Ensure rules are in DB
        all_rules = self._parser.get_all_rules()
        if not all_rules:
            logger.info("CRSDetector: no cached rules, parsing .conf files...")
            self._parser.load_rules(paranoia_level=paranoia_level)
            all_rules = self._parser.get_all_rules()

        self._crs_patterns = []
        for rule in all_rules.values():
            pattern_str = rule.get("pattern", "")
            if not pattern_str or rule["paranoia_level"] > paranoia_level:
                continue
            try:
                compiled = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
                self._crs_patterns.append((
                    rule["rule_id"],
                    rule["category"],
                    rule["severity"],
                    rule["description"],
                    compiled,
                ))
                if len(self._crs_patterns) >= self._max_crs:
                    break
            except re.error:
                pass  # skip rules whose PCRE doesn't compile in Python re

        self._loaded = True
        logger.info("CRSDetector: %d CRS patterns compiled", len(self._crs_patterns))
        return len(self._crs_patterns)

    def analyze_line(self, raw_line: str, save: bool = True) -> List[dict]:
        """
        Analyse a single raw log line.
        Returns a (possibly empty) list of alert dicts.
        If *save* is True, persists alerts to SQLite.
        """
        if not self._loaded:
            self.load()

        parsed = self._parse_apache_line(raw_line)
        if parsed is None:
            return []

        ip, method, url, status, ua = parsed
        # Decode URL for pattern matching
        decoded_url = urllib.parse.unquote_plus(url)
        
        # Split target domains:
        # SQLi, XSS, LFI, RFI, RCE target path/parameters only to avoid false positives in UA (e.g. semicolons)
        web_target  = f"{url} {decoded_url}"
        # Scanner & Protocol target headers/UA as well
        gen_target  = f"{url} {ua} {decoded_url}"

        alerts: List[dict] = []
        seen_ids: set = set()

        # 1. Heuristic layer (fast)
        for rid, cat, sev, desc, pattern in _HEURISTICS:
            if rid in seen_ids:
                continue
            curr_target = gen_target if cat in ("Scanner", "Protocol") else web_target
            m = pattern.search(curr_target)
            if m:
                alert = _make_alert(
                    rule_id=rid, category=cat, severity=sev,
                    description=desc, matched_pattern=m.group(0),
                    source_ip=ip, log_line=raw_line,
                    method=method, url=url, status=status, user_agent=ua,
                )
                alerts.append(alert)
                seen_ids.add(rid)

        # 2. CRS DB rule layer
        for rid, cat, sev, desc, pattern in self._crs_patterns:
            if rid in seen_ids:
                continue
            try:
                curr_target = gen_target if cat in ("Scanner", "Protocol") else web_target
                m = pattern.search(curr_target)
                if m:
                    alert = _make_alert(
                        rule_id=rid, category=cat, severity=sev,
                        description=desc, matched_pattern=m.group(0)[:200],
                        source_ip=ip, log_line=raw_line,
                        method=method, url=url, status=status, user_agent=ua,
                    )
                    alerts.append(alert)
                    seen_ids.add(rid)
            except Exception:
                pass

        if alerts and save:
            self._save_alerts(alerts)

        return alerts

    def analyze_file(
        self,
        filepath: str,
        save: bool = True,
        paranoia_level: int = 2,
    ) -> List[dict]:
        """
        Batch-analyse an entire log file.
        Returns aggregated list of all alerts found.
        """
        if not self._loaded:
            self.load(paranoia_level=paranoia_level)

        all_alerts: List[dict] = []
        path = Path(filepath)
        if not path.exists():
            logger.error("Log file not found: %s", filepath)
            return []

        logger.info("CRSDetector: scanning %s", filepath)
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                alerts = self.analyze_line(line, save=save)
                all_alerts.extend(alerts)

        logger.info("CRSDetector: %d alerts in %s", len(all_alerts), filepath)
        return all_alerts

    def get_recent_alerts(self, limit: int = 100) -> List[dict]:
        """Return the most recent *limit* alerts from the database."""
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM detected_attacks ORDER BY id DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error("get_recent_alerts: %s", e)
            return []

    def get_attack_stats(self) -> dict:
        """Aggregate statistics from the detected_attacks table."""
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.row_factory = sqlite3.Row

                total = conn.execute("SELECT COUNT(*) FROM detected_attacks").fetchone()[0]
                by_cat = conn.execute(
                    "SELECT category, COUNT(*) as n FROM detected_attacks GROUP BY category ORDER BY n DESC"
                ).fetchall()
                by_sev = conn.execute(
                    "SELECT severity, COUNT(*) as n FROM detected_attacks GROUP BY severity"
                ).fetchall()
                top_ips = conn.execute(
                    "SELECT source_ip, COUNT(*) as n FROM detected_attacks GROUP BY source_ip ORDER BY n DESC LIMIT 10"
                ).fetchall()
                top_rules = conn.execute(
                    "SELECT rule_id, category, description, COUNT(*) as n FROM detected_attacks GROUP BY rule_id ORDER BY n DESC LIMIT 10"
                ).fetchall()

            return {
                "total_alerts":   total,
                "by_category":    {r["category"]: r["n"] for r in by_cat},
                "by_severity":    {r["severity"]:  r["n"] for r in by_sev},
                "top_attacker_ips": [{"ip": r["source_ip"], "count": r["n"]} for r in top_ips],
                "top_triggered_rules": [
                    {"rule_id": r["rule_id"], "category": r["category"],
                     "description": r["description"], "count": r["n"]}
                    for r in top_rules
                ],
            }
        except Exception as e:
            logger.error("get_attack_stats: %s", e)
            return {"error": str(e)}

    # ── Parsing ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_apache_line(raw: str) -> Optional[Tuple[str, str, str, int, str]]:
        """
        Parse a Combined Log Format line.
        Returns (ip, method, url, status, user_agent) or None.
        """
        m = APACHE_RE.match(raw)
        if not m:
            return None
        ip     = m.group("ip")
        method = m.group("method")
        url    = m.group("url")
        try:
            status = int(m.group("status"))
        except ValueError:
            status = 0
        ua = m.group("ua") or ""
        return ip, method, url, status, ua

    # ── Database ──────────────────────────────────────────────────────────────

    def _ensure_alerts_table(self) -> None:
        from backend.models import ensure_all_tables
        try:
            ensure_all_tables()
        except Exception as e:
            logger.error("Failed to run ensure_all_tables: %s", e)
        ddl = """
        CREATE TABLE IF NOT EXISTS detected_attacks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            source_ip       TEXT,
            rule_id         INTEGER,
            category        TEXT,
            severity        TEXT,
            description     TEXT,
            matched_pattern TEXT,
            method          TEXT,
            url             TEXT,
            status_code     INTEGER,
            user_agent      TEXT,
            log_line        TEXT,
            blocked         INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_da_ip       ON detected_attacks(source_ip);
        CREATE INDEX IF NOT EXISTS idx_da_rule     ON detected_attacks(rule_id);
        CREATE INDEX IF NOT EXISTS idx_da_severity ON detected_attacks(severity);
        CREATE INDEX IF NOT EXISTS idx_da_ts       ON detected_attacks(timestamp);
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.executescript(ddl)

    def _save_alerts(self, alerts: List[dict]) -> None:
        sql = """
        INSERT INTO detected_attacks
            (timestamp, source_ip, rule_id, category, severity, description,
             matched_pattern, method, url, status_code, user_agent, log_line, blocked)
        VALUES
            (:timestamp, :source_ip, :rule_id, :category, :severity, :description,
             :matched_pattern, :method, :url, :status_code, :user_agent, :log_line, :blocked)
        """
        with sqlite3.connect(self._db_path) as conn:
            conn.executemany(sql, alerts)


# ─── Quick smoke-test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    det = CRSDetector()
    det.load(paranoia_level=2)

    test_lines = [
        # SQLi
        '192.168.1.50 - - [05/May/2026:21:14:41 +0500] "GET /admin.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        # XSS
        '10.0.0.5 - - [05/May/2026:21:15:00 +0500] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
        # LFI
        '45.33.32.156 - - [05/May/2026:21:15:10 +0500] "GET /page?file=../../../../etc/passwd HTTP/1.1" 403 300 "-" "python-requests/2.28"',
        # Scanner
        '91.108.4.180 - - [05/May/2026:21:15:20 +0500] "GET /phpmyadmin/ HTTP/1.1" 404 512 "-" "Nikto/2.1.6"',
        # Benign
        '192.168.1.1 - - [05/May/2026:21:16:00 +0500] "GET /index.html HTTP/1.1" 200 4096 "-" "Mozilla/5.0"',
    ]

    for line in test_lines:
        alerts = det.analyze_line(line, save=False)
        if alerts:
            for a in alerts:
                print(f"  [{a['severity']}] Rule {a['rule_id']} ({a['category']}) — {a['description'][:60]}")
        else:
            print("  [CLEAN] No threats detected")
