"""
ForensicLogX — ModSecurity Audit Log Parser
============================================
Parses ModSecurity audit log files (modsec_audit.log format) and converts
each transaction into a standardised alert dict that matches the schema used
by crs_detector.py.

ModSecurity audit log structure (parts A–K):
    --<boundary>-A--   Request header section (transaction ID, timestamp)
    --<boundary>-B--   Request body section
    --<boundary>-C--   (unused in default config)
    --<boundary>-D--   (unused)
    --<boundary>-E--   Response body (if body audit enabled)
    --<boundary>-F--   Response headers
    --<boundary>-G--   (unused)
    --<boundary>-H--   Audit log trailer (rule matches, anomaly scores)
    --<boundary>-I--   Reduced body substitute
    --<boundary>-J--   (unused)
    --<boundary>-K--   Matched rules list
    --<boundary>-Z--   End of transaction

Usage::
    from backend.modsec_log_parser import ModSecParser
    parser  = ModSecParser()
    entries = parser.parse_file("/var/log/modsec_audit.log")
    for e in entries:
        print(e["transaction_id"], e["alerts"])
"""

import re
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── Regex patterns for audit log fields ─────────────────────────────────────

# Section boundary:  --abc123de-A--
_BOUNDARY_RE = re.compile(r'^--([0-9a-fA-F]+)-([A-Z])--$')

# Section A — first line: "[timestamp] [pid] [client ip:port] [...]"
_SECTION_A_RE = re.compile(
    r'\[(?P<time>[^\]]+)\]\s+\[(?P<pid>\d+)\]\s+\[client\s+(?P<ip>[\d.]+)(?::\d+)?\]'
)

# Alternative timestamp from the audit log header line
_TIMESTAMP_RE = re.compile(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*)\]')

# Section H — trailer fields
_TRAILER_RE = {
    "anomaly_score":   re.compile(r'Inbound-Anomaly-Score:\s*(\d+)',    re.IGNORECASE),
    "anomaly_score_r": re.compile(r'Outbound-Anomaly-Score:\s*(\d+)',   re.IGNORECASE),
    "stopwatch":       re.compile(r'Stopwatch:\s*(\d+)',                re.IGNORECASE),
    "handler":         re.compile(r'Apache-Handler:\s*(\S+)',           re.IGNORECASE),
    "producer":        re.compile(r'Producer:\s*(.+)',                  re.IGNORECASE),
    "server":          re.compile(r'Server:\s*(.+)',                    re.IGNORECASE),
    "engine_mode":     re.compile(r'Engine-Mode:\s*"?([^"\n]+)"?',      re.IGNORECASE),
}

# Section H — rule match lines:
# [file "..."] [line "..."] [id "941100"] [msg "..."] [severity "..."] [tag "..."]
_RULE_MATCH_RE = re.compile(
    r'\[id\s+"(?P<id>\d+)"\].*?'
    r'(?:\[msg\s+"(?P<msg>[^"]*)"\])?.*?'
    r'(?:\[severity\s+"(?P<sev>[^"]*)"\])?',
    re.DOTALL
)
_TAG_RE  = re.compile(r'\[tag\s+"([^"]+)"\]')
_DATA_RE = re.compile(r'\[data\s+"([^"]+)"\]')

# Section B — request line:  "GET /path HTTP/1.1"
_REQUEST_LINE_RE = re.compile(r'^(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<proto>HTTP/\S+)')


# ─── Parser class ─────────────────────────────────────────────────────────────

class ModSecParser:
    """
    Parse ModSecurity audit logs into structured transaction dicts.

    Each returned dict contains:
        transaction_id, timestamp, source_ip, method, url, protocol,
        status_code, inbound_anomaly_score, outbound_anomaly_score,
        blocked, alerts (list of rule-match dicts), raw_sections (dict)
    """

    def __init__(self, crs_rules: Optional[Dict[int, dict]] = None) -> None:
        """
        Parameters
        ----------
        crs_rules : optional {rule_id: rule_dict} mapping from CRSParser.
                    If provided, each alert is enriched with CRS metadata.
        """
        self._crs_rules = crs_rules or {}

    # ── Public API ────────────────────────────────────────────────────────────

    def parse_file(self, filepath: str) -> List[dict]:
        """
        Parse an entire audit log file.
        Returns a list of transaction dicts.
        """
        path = Path(filepath)
        if not path.exists():
            logger.error("ModSecParser: file not found: %s", filepath)
            return []

        logger.info("ModSecParser: parsing %s", filepath)
        content = path.read_text(encoding="utf-8", errors="replace")
        transactions = self._split_transactions(content)

        results = []
        for txn_text in transactions:
            parsed = self._parse_transaction(txn_text)
            if parsed:
                results.append(parsed)

        logger.info("ModSecParser: %d transactions parsed", len(results))
        return results

    def parse_text(self, text: str) -> List[dict]:
        """Parse raw audit log text (useful for testing)."""
        transactions = self._split_transactions(text)
        return [t for txn in transactions if (t := self._parse_transaction(txn))]

    def to_detector_alerts(self, transactions: List[dict]) -> List[dict]:
        """
        Convert parsed ModSec transactions into the same alert format
        produced by CRSDetector.analyze_line().
        """
        alerts = []
        for txn in transactions:
            for rule_match in txn.get("alerts", []):
                alerts.append({
                    "timestamp":       txn.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                    "rule_id":         rule_match.get("rule_id"),
                    "category":        rule_match.get("category", "Unknown"),
                    "severity":        rule_match.get("severity", "MEDIUM"),
                    "description":     rule_match.get("msg", ""),
                    "matched_pattern": rule_match.get("data", ""),
                    "source_ip":       txn.get("source_ip", ""),
                    "method":          txn.get("method", ""),
                    "url":             txn.get("url", ""),
                    "status_code":     txn.get("status_code", 0),
                    "user_agent":      "",
                    "log_line":        txn.get("raw_sections", {}).get("B", "")[:200],
                    "blocked":         txn.get("blocked", False),
                    "transaction_id":  txn.get("transaction_id", ""),
                    "inbound_score":   txn.get("inbound_anomaly_score", 0),
                })
        return alerts

    # ── Internal parsing ──────────────────────────────────────────────────────

    @staticmethod
    def _split_transactions(text: str) -> List[str]:
        """
        Split raw audit log text on the --BOUNDARY-A-- opener.
        Each chunk begins with the A-section header.
        """
        # Transactions start with a line like --xxxxxxxx-A--
        pattern = re.compile(r'(?=^--[0-9a-fA-F]+-A--)', re.MULTILINE)
        parts = pattern.split(text)
        return [p.strip() for p in parts if p.strip()]

    def _parse_transaction(self, text: str) -> Optional[dict]:
        """Parse one transaction block (all sections A–Z)."""
        sections = self._split_sections(text)
        if not sections:
            return None

        # ── Section A (request headers meta) ─────────────────────────────────
        section_a = sections.get("A", "")
        txn_id = ""
        source_ip = ""
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Boundary line gives transaction ID
        first_line = section_a.split("\n")[0] if section_a else ""
        bm = _BOUNDARY_RE.match(first_line)
        if bm:
            txn_id = bm.group(1)

        # Timestamp from section A body
        ts_m = _TIMESTAMP_RE.search(section_a)
        if ts_m:
            timestamp = self._parse_timestamp(ts_m.group(1))

        # Client IP from section A
        ip_m = _SECTION_A_RE.search(section_a)
        if ip_m:
            source_ip = ip_m.group("ip")

        # ── Section B (request line + headers) ────────────────────────────────
        section_b = sections.get("B", "")
        method, url, protocol = "", "", ""
        # Skip the boundary line (--abcdef01-B--) and find the first HTTP request line
        for bline in section_b.splitlines():
            if _BOUNDARY_RE.match(bline):
                continue
            req_m = _REQUEST_LINE_RE.match(bline)
            if req_m:
                method   = req_m.group("method")
                url      = req_m.group("url")
                protocol = req_m.group("proto")
                break

        # ── Section F (response headers) ──────────────────────────────────────
        section_f = sections.get("F", "")
        status_code = 0
        status_m = re.search(r'HTTP/\S+\s+(\d{3})', section_f)
        if status_m:
            status_code = int(status_m.group(1))

        # ── Section H (audit trailer + rule matches) ───────────────────────────
        section_h = sections.get("H", "")
        trailer   = self._parse_trailer(section_h)
        rule_matches = self._parse_rule_matches(section_h)

        inbound_score  = int(trailer.get("anomaly_score",   0) or 0)
        outbound_score = int(trailer.get("anomaly_score_r", 0) or 0)
        blocked = inbound_score >= 5  # default CRS blocking threshold

        # ── Section K (matched rules list — more complete) ────────────────────
        section_k = sections.get("K", "")
        if section_k and not rule_matches:
            rule_matches = self._parse_rule_matches(section_k)

        # Enrich rule matches with CRS metadata
        for rm in rule_matches:
            rid = rm.get("rule_id")
            if rid and rid in self._crs_rules:
                crs = self._crs_rules[rid]
                rm.setdefault("category", crs.get("category", "Unknown"))
                rm.setdefault("severity", crs.get("severity", "MEDIUM"))

        return {
            "transaction_id":       txn_id,
            "timestamp":            timestamp,
            "source_ip":            source_ip,
            "method":               method,
            "url":                  url,
            "protocol":             protocol,
            "status_code":          status_code,
            "inbound_anomaly_score":  inbound_score,
            "outbound_anomaly_score": outbound_score,
            "blocked":              blocked,
            "alerts":               rule_matches,
            "trailer":              trailer,
            "raw_sections":         {k: v[:500] for k, v in sections.items()},
        }

    @staticmethod
    def _split_sections(text: str) -> Dict[str, str]:
        """
        Split a transaction block into {section_letter: content} dict.
        """
        sections: Dict[str, str] = {}
        current_letter: Optional[str] = None
        current_lines:  List[str]     = []

        for line in text.splitlines():
            bm = _BOUNDARY_RE.match(line)
            if bm:
                if current_letter is not None:
                    sections[current_letter] = "\n".join(current_lines)
                current_letter = bm.group(2)
                current_lines  = [line]
            else:
                if current_letter is not None:
                    current_lines.append(line)

        if current_letter is not None:
            sections[current_letter] = "\n".join(current_lines)

        return sections

    @staticmethod
    def _parse_trailer(section_h: str) -> dict:
        """Extract key-value fields from the H (trailer) section."""
        trailer = {}
        for key, pattern in _TRAILER_RE.items():
            m = pattern.search(section_h)
            if m:
                trailer[key] = m.group(1).strip()
        return trailer

    @staticmethod
    def _parse_rule_matches(section: str) -> List[dict]:
        """
        Parse rule-match lines from section H or K.
        Returns list of {rule_id, msg, severity, tags, data} dicts.
        """
        matches = []
        # Each match spans one line starting with "Message:" or containing [id "..."]
        for line in section.splitlines():
            id_m = re.search(r'\[id\s+"(\d+)"\]', line)
            if not id_m:
                continue
            rule_id = int(id_m.group(1))
            msg_m   = re.search(r'\[msg\s+"([^"]*)"\]', line)
            sev_m   = re.search(r'\[severity\s+"([^"]*)"\]', line)
            tags    = _TAG_RE.findall(line)
            data    = _DATA_RE.search(line)

            from backend.crs_parser import SEVERITY_MAP
            severity_raw = (sev_m.group(1).lower() if sev_m else "notice")
            severity     = SEVERITY_MAP.get(severity_raw, "LOW")

            matches.append({
                "rule_id":  rule_id,
                "msg":      msg_m.group(1) if msg_m else "",
                "severity": severity,
                "tags":     tags,
                "data":     data.group(1) if data else "",
                "category": "Unknown",   # enriched later from CRS DB
            })

        return matches

    @staticmethod
    def _parse_timestamp(ts_str: str) -> str:
        """
        Convert ModSecurity timestamp (e.g. '05/May/2026:21:14:41 +0500')
        to ISO-8601 UTC string.
        """
        try:
            # Strip timezone offset for simplicity
            ts_clean = re.sub(r'\s+[+-]\d{4}$', '', ts_str.strip())
            dt = datetime.strptime(ts_clean, "%d/%b/%Y:%H:%M:%S")
            return dt.isoformat() + "Z"
        except ValueError:
            return datetime.utcnow().isoformat() + "Z"


# ─── Example / smoke-test ─────────────────────────────────────────────────────

SAMPLE_AUDIT_LOG = """
--abcdef01-A--
[05/May/2026:21:14:41 +0500] [1234] [client 192.168.1.50:54321] ModSecurity: Warning.
--abcdef01-B--
GET /admin.php?id=1' OR '1'='1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0

--abcdef01-F--
HTTP/1.1 200 OK
Content-Type: text/html

--abcdef01-H--
Message: Warning. Pattern match "(?i)(?:union..." at ARGS:id. [file "/etc/apache2/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "45"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "1' OR '1'='1"] [severity "CRITICAL"] [ver "OWASP_CRS/4.27.0-dev"] [tag "attack-sqli"] [tag "OWASP_CRS"] [tag "paranoia-level/1"]
Stopwatch: 1714933481123456 12345 (- - -)
Stopwatch2: 1714933481123456 12345; combined=5120, p1=128, p2=4992, p3=0, p4=0, p5=0, sr=0, sw=0, l=0, gc=0
Producer: ModSecurity for Apache/2.9.7 (http://www.modsecurity.org/).
Server: Apache/2.4.58 (Ubuntu)
Engine-Mode: "DETECTION_ONLY"
Inbound-Anomaly-Score: 5
Outbound-Anomaly-Score: 0

--abcdef01-Z--
""".strip()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = ModSecParser()
    txns = parser.parse_text(SAMPLE_AUDIT_LOG)
    for txn in txns:
        print(f"Transaction: {txn['transaction_id']}")
        print(f"  IP:     {txn['source_ip']}")
        print(f"  URL:    {txn['url']}")
        print(f"  Score:  {txn['inbound_anomaly_score']}")
        print(f"  Alerts: {len(txn['alerts'])}")
        for a in txn["alerts"]:
            print(f"    Rule {a['rule_id']}: [{a['severity']}] {a['msg']}")
