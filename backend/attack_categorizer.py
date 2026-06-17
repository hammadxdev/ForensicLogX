"""
ForensicLogX — Attack Categorisation Engine
============================================
Maps CRS rule IDs → MITRE ATT&CK techniques, enriches alert dicts with
MITRE context, detects attack chains, and correlates multi-rule violations
from the same IP into campaign summaries.

References:
    MITRE ATT&CK Enterprise: https://attack.mitre.org/
    MITRE ATT&CK for ICS:    https://attack.mitre.org/matrices/ics/
    CAPEC:                   https://capec.mitre.org/

Usage::
    from backend.attack_categorizer import AttackCategorizer
    cat = AttackCategorizer()

    # Enrich a single alert
    enriched = cat.enrich(alert_dict)

    # Categorise a batch
    enriched_list = cat.enrich_batch(alerts)

    # Detect attack chains from a session of alerts
    chains = cat.detect_chains(alerts, window_seconds=300)

    # Campaign summary per source IP
    campaigns = cat.summarise_by_ip(alerts)
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple


# ─── MITRE ATT&CK / CAPEC Mapping ────────────────────────────────────────────
#
# Structure:
#   rule_prefix (int): first N digits of rule ID → MITRE dict
#   or exact rule ID → MITRE dict
#
# MITRE dict keys:
#   technique_id, technique_name, tactic, tactic_id, capec_id, references

_MITRE_BY_PREFIX: Dict[int, dict] = {
    # ── 930xxx — LFI ─────────────────────────────────────────────────────────
    9301: {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "capec_id":       "CAPEC-252",
        "mitre_url":      "https://attack.mitre.org/techniques/T1083/",
    },
    # ── 931xxx — RFI ─────────────────────────────────────────────────────────
    9311: {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-253",
        "mitre_url":      "https://attack.mitre.org/techniques/T1190/",
    },
    # ── 932xxx — RCE ─────────────────────────────────────────────────────────
    9321: {
        "technique_id":   "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic":         "Execution",
        "tactic_id":      "TA0002",
        "capec_id":       "CAPEC-88",
        "mitre_url":      "https://attack.mitre.org/techniques/T1059/",
    },
    # ── 933xxx — PHP Injection ────────────────────────────────────────────────
    9331: {
        "technique_id":   "T1059.004",
        "technique_name": "Unix Shell",
        "tactic":         "Execution",
        "tactic_id":      "TA0002",
        "capec_id":       "CAPEC-86",
        "mitre_url":      "https://attack.mitre.org/techniques/T1059/004/",
    },
    # ── 941xxx — XSS ─────────────────────────────────────────────────────────
    9411: {
        "technique_id":   "T1189",
        "technique_name": "Drive-by Compromise",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-86",
        "mitre_url":      "https://attack.mitre.org/techniques/T1189/",
    },
    # ── 942xxx — SQLi ────────────────────────────────────────────────────────
    9421: {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-66",
        "mitre_url":      "https://attack.mitre.org/techniques/T1190/",
    },
    # ── 943xxx — Session Fixation ─────────────────────────────────────────────
    9431: {
        "technique_id":   "T1563",
        "technique_name": "Remote Service Session Hijacking",
        "tactic":         "Lateral Movement",
        "tactic_id":      "TA0008",
        "capec_id":       "CAPEC-61",
        "mitre_url":      "https://attack.mitre.org/techniques/T1563/",
    },
    # ── 944xxx — Java Injection ───────────────────────────────────────────────
    9441: {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-242",
        "mitre_url":      "https://attack.mitre.org/techniques/T1190/",
    },
    # ── 913xxx — Scanner Detection ────────────────────────────────────────────
    9131: {
        "technique_id":   "T1595",
        "technique_name": "Active Scanning",
        "tactic":         "Reconnaissance",
        "tactic_id":      "TA0043",
        "capec_id":       "CAPEC-309",
        "mitre_url":      "https://attack.mitre.org/techniques/T1595/",
    },
    # ── 920/921xx — Protocol Enforcement ──────────────────────────────────────
    9201: {
        "technique_id":   "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic":         "Command and Control",
        "tactic_id":      "TA0011",
        "capec_id":       "CAPEC-33",
        "mitre_url":      "https://attack.mitre.org/techniques/T1071/",
    },
    # ── 955xxx — Web Shell ────────────────────────────────────────────────────
    9551: {
        "technique_id":   "T1505.003",
        "technique_name": "Web Shell",
        "tactic":         "Persistence",
        "tactic_id":      "TA0003",
        "capec_id":       "CAPEC-86",
        "mitre_url":      "https://attack.mitre.org/techniques/T1505/003/",
    },
    # ── 950/951/952/953/954/956xx — Data Leakage ──────────────────────────────
    9501: {
        "technique_id":   "T1213",
        "technique_name": "Data from Information Repositories",
        "tactic":         "Collection",
        "tactic_id":      "TA0009",
        "capec_id":       "CAPEC-217",
        "mitre_url":      "https://attack.mitre.org/techniques/T1213/",
    },
}

# Exact rule overrides for specific high-value rules
# Exact rule overrides for specific high-value rules
_MITRE_EXACT: Dict[int, dict] = {
    932110: {  # Log4Shell
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application (Log4Shell CVE-2021-44228)",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-242",
        "mitre_url":      "https://attack.mitre.org/techniques/T1190/",
        "cve":            "CVE-2021-44228",
    },
    942100: {  # SQLi via libinjection
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application (SQL Injection)",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-66",
        "mitre_url":      "https://attack.mitre.org/techniques/T1190/",
    },
    941100: {  # XSS via libinjection
        "technique_id":   "T1189",
        "technique_name": "Drive-by Compromise (Reflected XSS)",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-86",
        "mitre_url":      "https://attack.mitre.org/techniques/T1189/",
    },
    # ── Custom DVWA overrides ────────────────────────────────────────────────
    950110: {  # CSRF
        "technique_id":   "T1204.001",
        "technique_name": "User Execution: Malicious Link",
        "tactic":         "Execution",
        "tactic_id":      "TA0002",
        "capec_id":       "CAPEC-62",
        "mitre_url":      "https://attack.mitre.org/techniques/T1204/001/",
    },
    950120: {  # CAPTCHA
        "technique_id":   "T1110",
        "technique_name": "Brute Force Bypass",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "capec_id":       "CAPEC-119",
        "mitre_url":      "https://attack.mitre.org/techniques/T1110/",
    },
    950130: {  # CSP Bypass
        "technique_id":   "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "tactic":         "Defense Evasion",
        "tactic_id":      "TA0005",
        "capec_id":       "CAPEC-509",
        "mitre_url":      "https://attack.mitre.org/techniques/T1562/001/",
    },
    950140: {  # JavaScript Attacks
        "technique_id":   "T1059.007",
        "technique_name": "JavaScript Execution",
        "tactic":         "Execution",
        "tactic_id":      "TA0002",
        "capec_id":       "CAPEC-242",
        "mitre_url":      "https://attack.mitre.org/techniques/T1059/007/",
    },
    950150: {  # Authorisation Bypass
        "technique_id":   "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic":         "Privilege Escalation",
        "tactic_id":      "TA0004",
        "capec_id":       "CAPEC-233",
        "mitre_url":      "https://attack.mitre.org/techniques/T1548/",
    },
    950160: {  # Open Redirect
        "technique_id":   "T1566",
        "technique_name": "Phishing (Open Redirect)",
        "tactic":         "Initial Access",
        "tactic_id":      "TA0001",
        "capec_id":       "CAPEC-127",
        "mitre_url":      "https://attack.mitre.org/techniques/T1566/",
    },
    950170: {  # Cryptography
        "technique_id":   "T1552",
        "technique_name": "Unsecured Credentials",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "capec_id":       "CAPEC-97",
        "mitre_url":      "https://attack.mitre.org/techniques/T1552/",
    },
    950180: {  # API
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "capec_id":       "CAPEC-640",
        "mitre_url":      "https://attack.mitre.org/techniques/T1046/",
    },
    999100: {  # Brute Force
        "technique_id":   "T1110",
        "technique_name": "Brute Force Login",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "capec_id":       "CAPEC-112",
        "mitre_url":      "https://attack.mitre.org/techniques/T1110/",
    },
}

# ── Attack family → broad OWASP / CAPEC category ─────────────────────────────
_CATEGORY_META: Dict[str, dict] = {
    "SQL Injection":         {"owasp": "A03:2021 – Injection",               "risk": "CRITICAL"},
    "SQL Injection (Blind)": {"owasp": "A03:2021 – Injection",               "risk": "CRITICAL"},
    "XSS (Reflected)":       {"owasp": "A03:2021 – Injection",               "risk": "HIGH"},
    "XSS (Stored)":          {"owasp": "A03:2021 – Injection",               "risk": "HIGH"},
    "XSS (DOM)":             {"owasp": "A03:2021 – Injection",               "risk": "HIGH"},
    "CSRF":                  {"owasp": "A01:2021 – Broken Access Control",   "risk": "HIGH"},
    "File Inclusion":        {"owasp": "A01:2021 – Broken Access Control",   "risk": "HIGH"},
    "File Upload":           {"owasp": "A01:2021 – Broken Access Control",   "risk": "CRITICAL"},
    "Insecure CAPTCHA":      {"owasp": "A07:2021 – Auth Failures",           "risk": "MEDIUM"},
    "Weak Session IDs":      {"owasp": "A07:2021 – Auth Failures",           "risk": "HIGH"},
    "CSP Bypass":            {"owasp": "A05:2021 – Security Misconfiguration","risk": "MEDIUM"},
    "JavaScript Attacks":    {"owasp": "A03:2021 – Injection",               "risk": "HIGH"},
    "Authorisation Bypass":  {"owasp": "A01:2021 – Broken Access Control",   "risk": "CRITICAL"},
    "Open HTTP Redirect":    {"owasp": "A01:2021 – Broken Access Control",   "risk": "MEDIUM"},
    "Cryptography":          {"owasp": "A02:2021 – Cryptographic Failures",  "risk": "HIGH"},
    "API":                   {"owasp": "A01:2021 – Broken Access Control",   "risk": "HIGH"},
    "Brute Force":           {"owasp": "A07:2021 – Auth Failures",           "risk": "HIGH"},
    "Command Injection":     {"owasp": "A03:2021 – Injection",               "risk": "CRITICAL"},
    
    # Legacy fallbacks
    "SQLi":                  {"owasp": "A03:2021 – Injection",               "risk": "CRITICAL"},
    "XSS":                   {"owasp": "A03:2021 – Injection",               "risk": "HIGH"},
    "LFI":                   {"owasp": "A01:2021 – Broken Access Control",   "risk": "HIGH"},
    "RFI":                   {"owasp": "A01:2021 – Broken Access Control",   "risk": "HIGH"},
    "RCE":                   {"owasp": "A03:2021 – Injection",               "risk": "CRITICAL"},
    "PHPInjection":          {"owasp": "A03:2021 – Injection",               "risk": "HIGH"},
    "JavaInjection":         {"owasp": "A06:2021 – Vulnerable Components",   "risk": "CRITICAL"},
    "SessionFixation":       {"owasp": "A07:2021 – Auth Failures",           "risk": "MEDIUM"},
    "Scanner":               {"owasp": "A05:2021 – Security Misconfiguration","risk": "MEDIUM"},
    "Protocol":              {"owasp": "A05:2021 – Security Misconfiguration","risk": "LOW"},
    "WebShell":              {"owasp": "A01:2021 – Broken Access Control",   "risk": "CRITICAL"},
    "Data Leakage":          {"owasp": "A02:2021 – Cryptographic Failures",  "risk": "HIGH"},
}

# ── Attack chain sequences (ordered list of categories implies a campaign) ────
_CHAIN_SEQUENCES: List[Tuple[str, str, str]] = [
    # (first_category, second_category, chain_name)
    ("Scanner",  "SQL Injection",         "Recon -> SQL Injection Campaign"),
    ("Scanner",  "XSS (Reflected)",       "Recon -> Reflected XSS Campaign"),
    ("Scanner",  "XSS (Stored)",          "Recon -> Stored XSS Campaign"),
    ("Scanner",  "File Inclusion",        "Recon -> File Disclosure Campaign"),
    ("Scanner",  "Command Injection",     "Recon -> Remote Code Execution Campaign"),
    ("SQL Injection",     "File Upload",   "SQL Injection -> Web Shell Deployment"),
    ("File Inclusion",    "Command Injection", "File Disclosure -> Code Execution Chain"),
    ("XSS (Reflected)",   "Weak Session IDs",  "XSS -> Session Hijack Chain"),
    ("Command Injection", "File Upload",   "RCE -> Persistent Shell Chain"),
]


class AttackCategorizer:
    """
    Enrich alert dicts with MITRE ATT&CK context and detect attack chains.
    """

    def __init__(self) -> None:
        pass

    # ── Public API ────────────────────────────────────────────────────────────

    def enrich(self, alert: dict) -> dict:
        """
        Return a copy of *alert* with added 'mitre' and 'owasp' keys.
        """
        alert = dict(alert)
        rule_id  = alert.get("rule_id", 0)
        category = alert.get("category", "Unknown")

        mitre = self._lookup_mitre(rule_id)
        owasp = _CATEGORY_META.get(category, {})

        alert["mitre"] = mitre
        alert["owasp"] = owasp.get("owasp", "")
        alert["risk_rating"] = owasp.get("risk", alert.get("severity", "MEDIUM"))

        return alert

    def enrich_batch(self, alerts: List[dict]) -> List[dict]:
        """Enrich a list of alerts with MITRE context."""
        return [self.enrich(a) for a in alerts]

    def detect_chains(
        self,
        alerts: List[dict],
        window_seconds: int = 300,
    ) -> List[dict]:
        """
        Identify multi-stage attack chains within *window_seconds*.

        Returns a list of chain dicts:
            {
                "chain_name":   str,
                "source_ip":    str,
                "start_time":   str,
                "end_time":     str,
                "alert_ids":    [int, ...],
                "severity":     "CRITICAL" | "HIGH",
            }
        """
        # Group by source IP
        by_ip: Dict[str, List[dict]] = defaultdict(list)
        for a in alerts:
            by_ip[a.get("source_ip", "")].append(a)

        chains = []
        for ip, ip_alerts in by_ip.items():
            if not ip:
                continue
            # Sort by timestamp
            ip_alerts = sorted(ip_alerts, key=lambda x: x.get("timestamp", ""))
            chains += self._find_chains_for_ip(ip, ip_alerts, window_seconds)

        return chains

    def summarise_by_ip(self, alerts: List[dict]) -> List[dict]:
        """
        Aggregate alerts by source IP into campaign summaries.

        Returns a list sorted by total_alerts descending.
        """
        by_ip: Dict[str, dict] = defaultdict(lambda: {
            "source_ip":       "",
            "total_alerts":    0,
            "categories":      defaultdict(int),
            "severities":      defaultdict(int),
            "rule_ids":        set(),
            "first_seen":      None,
            "last_seen":       None,
            "attack_chain":    [],
        })

        for a in alerts:
            ip = a.get("source_ip", "unknown")
            d  = by_ip[ip]
            d["source_ip"]     = ip
            d["total_alerts"] += 1
            d["categories"][a.get("category", "Unknown")] += 1
            d["severities"][a.get("severity",  "MEDIUM")]  += 1
            d["rule_ids"].add(a.get("rule_id", 0))

            ts = a.get("timestamp")
            if ts:
                if d["first_seen"] is None or ts < d["first_seen"]:
                    d["first_seen"] = ts
                if d["last_seen"] is None or ts > d["last_seen"]:
                    d["last_seen"] = ts

        summaries = []
        for ip, d in by_ip.items():
            summaries.append({
                "source_ip":    ip,
                "total_alerts": d["total_alerts"],
                "categories":   dict(d["categories"]),
                "severities":   dict(d["severities"]),
                "rule_ids":     sorted(d["rule_ids"]),
                "first_seen":   d["first_seen"],
                "last_seen":    d["last_seen"],
                "risk_score":   self._risk_score(d),
            })

        return sorted(summaries, key=lambda x: x["total_alerts"], reverse=True)

    def categorise_rule_id(self, rule_id: int) -> str:
        """Return the broad attack category for a CRS rule ID."""
        prefix = rule_id // 100
        mapping = {
            9301: "File Inclusion",     9302: "File Inclusion",
            9311: "File Inclusion",
            9321: "Command Injection",  9322: "Command Injection",
            9331: "Command Injection",
            9341: "SQL Injection",
            9411: "XSS (Reflected)",
            9412: "XSS (DOM)",
            9421: "SQL Injection",
            9431: "Weak Session IDs",
            9441: "Command Injection",
            9131: "Scanner",
            9201: "Protocol",           9211: "Protocol",
            9551: "File Upload",
            9501: "Data Leakage",       9511: "Data Leakage",
            9521: "Data Leakage",       9531: "Data Leakage",
            9541: "Data Leakage",       9561: "Data Leakage",
        }
        return mapping.get(prefix, "Unknown")

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _lookup_mitre(rule_id: int) -> dict:
        """Return MITRE dict for a rule_id, using exact then prefix lookup."""
        if rule_id in _MITRE_EXACT:
            return _MITRE_EXACT[rule_id]
        prefix = rule_id // 100
        if prefix in _MITRE_BY_PREFIX:
            return dict(_MITRE_BY_PREFIX[prefix])
        # Try 3-digit prefix group (e.g. 9301 → 930)
        prefix3 = rule_id // 1000
        for p, v in _MITRE_BY_PREFIX.items():
            if p // 10 == prefix3:
                return dict(v)
        return {}

    @staticmethod
    def _find_chains_for_ip(
        ip: str,
        alerts: List[dict],
        window: int,
    ) -> List[dict]:
        """Detect sequential attack patterns for one IP within the time window."""
        chains = []
        categories = [a.get("category", "") for a in alerts]

        for first_cat, second_cat, chain_name in _CHAIN_SEQUENCES:
            try:
                idx1 = categories.index(first_cat)
                idx2 = next(
                    i for i in range(idx1 + 1, len(categories))
                    if categories[i] == second_cat
                )
            except (ValueError, StopIteration):
                continue

            a1, a2 = alerts[idx1], alerts[idx2]
            t1 = a1.get("timestamp", "")
            t2 = a2.get("timestamp", "")

            # Time-window check (soft — skip if timestamps missing)
            within_window = True
            try:
                dt1 = datetime.fromisoformat(t1.replace("Z", ""))
                dt2 = datetime.fromisoformat(t2.replace("Z", ""))
                within_window = abs((dt2 - dt1).total_seconds()) <= window
            except (ValueError, AttributeError):
                pass

            if within_window:
                chains.append({
                    "chain_name": chain_name,
                    "source_ip":  ip,
                    "start_time": t1,
                    "end_time":   t2,
                    "categories": [first_cat, second_cat],
                    "severity":   "CRITICAL",
                })

        return chains

    @staticmethod
    def _risk_score(d: dict) -> int:
        """Compute a simple 0-100 risk score for an IP campaign summary."""
        score = 0
        sev_weights = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1}
        for sev, count in d["severities"].items():
            score += sev_weights.get(sev, 1) * count
        score += len(d["categories"]) * 5   # diversity bonus
        return min(score, 100)


# ─── Quick demo ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cat = AttackCategorizer()

    sample_alerts = [
        {"rule_id": 913100, "category": "Scanner",  "severity": "MEDIUM",
         "source_ip": "91.108.4.180", "timestamp": "2026-05-05T21:00:00Z"},
        {"rule_id": 942100, "category": "SQLi",     "severity": "CRITICAL",
         "source_ip": "91.108.4.180", "timestamp": "2026-05-05T21:02:00Z"},
        {"rule_id": 941100, "category": "XSS",      "severity": "CRITICAL",
         "source_ip": "10.0.0.5",     "timestamp": "2026-05-05T21:05:00Z"},
        {"rule_id": 930100, "category": "LFI",      "severity": "HIGH",
         "source_ip": "45.33.32.156", "timestamp": "2026-05-05T21:10:00Z"},
    ]

    enriched = cat.enrich_batch(sample_alerts)
    print("=== Enriched Alerts ===")
    for a in enriched:
        mitre = a.get("mitre", {})
        print(f"  Rule {a['rule_id']:>7}  [{a['severity']:<8}] "
              f"{a['category']:<20}  MITRE: {mitre.get('technique_id','N/A')} "
              f"— {mitre.get('technique_name','')[:40]}")

    chains = cat.detect_chains(sample_alerts)
    print("\n=== Attack Chains ===")
    for c in chains:
        print(f"  [{c['severity']}] {c['chain_name']}  (IP: {c['source_ip']})")

    campaigns = cat.summarise_by_ip(sample_alerts)
    print("\n=== IP Campaigns ===")
    for c in campaigns:
        print(f"  {c['source_ip']:<18} alerts={c['total_alerts']}  "
              f"risk={c['risk_score']}  cats={list(c['categories'].keys())}")
