"""
ForensicLogX — Threat Detection Engine
Rule-based signatures and heuristics targeting 30+ threat categories.
Uses detection_rules.py, regex_library.py, and fp_handler.py.
"""

import pandas as pd
import urllib.parse
from datetime import timedelta
from backend.config import Config
from backend.detection_rules import DETECTION_RULES
from backend.regex_library import REGEX_LIBRARY
from backend.ioc_library import SUSPICIOUS_USER_AGENTS, MALICIOUS_PATH_FRAGMENTS, THRESHOLD_CONFIGS
from backend.fp_handler import FalsePositiveHandler

fp_handler = FalsePositiveHandler()

def _severity(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 50: return "high"
    if score >= 20: return "medium"
    return "low"

def _create_threat_event(rule_id: str, ip: str, count: int, detail: str, timestamp: str, last_seen: str, urls: dict, user_agent: str, method: str, url: str, status_code: int, log_line: str) -> dict:
    """Helper to construct a threat event dict with confidence evaluation from fp_handler."""
    rule = DETECTION_RULES.get(rule_id, {})
    base_confidence = rule.get("confidence", 70)
    severity = rule.get("severity", "MEDIUM")
    
    # Evaluate false positive and confidence score
    evaluation = fp_handler.evaluate_alert(
        rule_id=rule_id,
        base_confidence=base_confidence,
        ip=ip,
        user_agent=user_agent,
        url=url
    )
    
    mitre = rule.get("mitre", {})
    rec = rule.get("recommendation", {}).get("remediation", "Investigate the alert and restrict access.")
    
    return {
        "id": f"{rule_id}:{ip}:{timestamp[-8:]}",
        "rule_id": rule_id,
        "type": rule.get("attack_type", rule.get("name", "Unknown Attack")),
        "category": rule.get("category", "Other"),
        "severity": severity.lower(),
        "ip": ip,
        "count": count,
        "detail": detail,
        "urls": urls,
        "timestamp": timestamp,
        "last_seen": last_seen,
        "method": method,
        "url": url,
        "status_code": status_code,
        "user_agent": user_agent,
        "log_line": log_line,
        "confidence_score": evaluation["confidence_score"],
        "false_positive_flag": evaluation["false_positive_flag"],
        "fp_reason": evaluation["reason"],
        "mitre_tactic": mitre.get("tactic", ""),
        "mitre_technique_id": mitre.get("technique_id", ""),
        "recommendation": rec
    }

# ─── 1. Authentication Attacks ───────────────────────────────────────────────

def detect_brute_force(df: pd.DataFrame) -> list[dict]:
    threats = []
    auth_fail = df[df["status"].isin([401, 403])].copy()
    if auth_fail.empty:
        return threats
    
    grouped = auth_fail.groupby("ip")
    for ip, group in grouped:
        count = len(group)
        if count >= THRESHOLD_CONFIGS["brute_force"]["count"]:
            detail = f"Brute force attempt: {count} authentication failures (401/403) from {ip}."
            urls = group["url"].value_counts().head(3).to_dict()
            first = group.iloc[0]
            threats.append(_create_threat_event(
                "FLX-001", ip, count, detail,
                str(group["timestamp"].min()), str(group["timestamp"].max()),
                urls, first["user_agent"], first["method"], first["url"], int(first["status"]), first["raw"]
            ))
    return threats

def detect_credential_stuffing(df: pd.DataFrame) -> list[dict]:
    threats = []
    auth_fail = df[df["status"].isin([401, 403])].copy()
    if auth_fail.empty:
        return threats
    
    # Stuffing: >5 users targeted by 1 IP
    for ip, group in auth_fail.groupby("ip"):
        unique_users = group["user"].nunique()
        if unique_users >= THRESHOLD_CONFIGS["credential_stuffing"]["unique_users"]:
            count = len(group)
            detail = f"Credential stuffing indicators: {count} attempts targeting {unique_users} unique usernames from {ip}."
            urls = group["url"].value_counts().head(3).to_dict()
            first = group.iloc[0]
            threats.append(_create_threat_event(
                "FLX-002", ip, count, detail,
                str(group["timestamp"].min()), str(group["timestamp"].max()),
                urls, first["user_agent"], first["method"], first["url"], int(first["status"]), first["raw"]
            ))
    return threats

def detect_password_spraying(df: pd.DataFrame) -> list[dict]:
    threats = []
    auth_fail = df[df["status"].isin([401, 403])].copy()
    if auth_fail.empty:
        return threats
    
    # Spraying: 1 username targeted by >10 unique IPs
    for user, group in auth_fail.groupby("user"):
        if user == "-":
            continue
        unique_ips = group["ip"].nunique()
        if unique_ips >= THRESHOLD_CONFIGS["password_spraying"]["unique_ips"]:
            count = len(group)
            detail = f"Password spraying indicators: Username '{user}' targeted from {unique_ips} unique IPs."
            urls = group["url"].value_counts().head(3).to_dict()
            first = group.iloc[0]
            threats.append(_create_threat_event(
                "FLX-003", "Multiple", count, detail,
                str(group["timestamp"].min()), str(group["timestamp"].max()),
                urls, first["user_agent"], first["method"], first["url"], int(first["status"]), first["raw"]
            ))
    return threats


# ─── Regex Based Detections (Generic Helper) ──────────────────────────────────

def _detect_by_regex(df: pd.DataFrame, rule_id: str, regex_key: str, column: str = "url") -> list[dict]:
    threats = []
    pattern = REGEX_LIBRARY.get(regex_key)
    if not pattern or df.empty:
        return threats
    
    # URL decode values to handle url-encoded symbols and plus signs
    def decode_val(x):
        val_str = str(x)
        try:
            return urllib.parse.unquote_plus(val_str)
        except Exception:
            return val_str

    mask = df[column].apply(lambda x: bool(pattern.search(decode_val(x))))
    matches = df[mask].copy()
    
    if matches.empty:
        return threats
    
    for ip, group in matches.groupby("ip"):
        count = len(group)
        detail = f"Signature match for {DETECTION_RULES[rule_id]['name']} in {column} from {ip}."
        urls = group["url"].value_counts().head(5).to_dict()
        first = group.iloc[0]
        threats.append(_create_threat_event(
            rule_id, ip, count, detail,
            str(group["timestamp"].min()), str(group["timestamp"].max()),
            urls, first["user_agent"], first["method"], first["url"], int(first["status"]), first["raw"]
        ))
    return threats


# ─── Port Scan & DDoS Heuristics ──────────────────────────────────────────────

def detect_port_scan_indicators(df: pd.DataFrame) -> list[dict]:
    threats = []
    # If the virtual host column exists and has non-standard values (e.g. port scan queries targeting multiple services),
    # or if request URL contains non-standard port connections, or multiple distinct port configurations
    # We can also check if status is 400 with invalid protocol
    bad_reqs = df[df["status"] == 400].copy()
    if bad_reqs.empty:
        return threats
    
    for ip, group in bad_reqs.groupby("ip"):
        count = len(group)
        if count >= 5:
            detail = f"Port scanning footprints: {count} invalid requests (HTTP 400) from {ip}."
            urls = group["url"].value_counts().head(3).to_dict()
            first = group.iloc[0]
            threats.append(_create_threat_event(
                "FLX-022", ip, count, detail,
                str(group["timestamp"].min()), str(group["timestamp"].max()),
                urls, first["user_agent"], first["method"], first["url"], int(first["status"]), first["raw"]
            ))
    return threats

def detect_ddos_indicators(df: pd.DataFrame) -> list[dict]:
    threats = []
    if df.empty:
        return threats
    
    df2 = df.copy()
    df2["minute"] = df2["timestamp"].dt.floor("min")
    counts = df2.groupby(["ip", "minute"]).size().reset_index(name="req_count")
    
    ddos_ips = counts[counts["req_count"] >= THRESHOLD_CONFIGS["ddos"]["requests_per_minute"]]
    for _, row in ddos_ips.drop_duplicates("ip").iterrows():
        ip = row["ip"]
        rpm = int(row["req_count"])
        detail = f"DDoS indicators: IP {ip} sent {rpm} requests in 1 minute window (Threshold: {THRESHOLD_CONFIGS['ddos']['requests_per_minute']}/min)."
        sub_df = df[df["ip"] == ip]
        urls = sub_df["url"].value_counts().head(3).to_dict()
        first = sub_df.iloc[0]
        threats.append(_create_threat_event(
            "FLX-024", ip, rpm, detail,
            str(sub_df["timestamp"].min()), str(sub_df["timestamp"].max()),
            urls, first["user_agent"], first["method"], first["url"], int(first["status"]), first["raw"]
        ))
    return threats

def detect_error_storm(df: pd.DataFrame) -> list[dict]:
    threats = []
    errors_5xx = df[df["status"] >= 500]
    if len(errors_5xx) >= Config.ERROR_STORM_THRESHOLD:
        detail = f"Error Storm: {len(errors_5xx)} server-side errors (5xx) detected (Threshold: {Config.ERROR_STORM_THRESHOLD})."
        urls = errors_5xx["url"].value_counts().head(3).to_dict()
        first = errors_5xx.iloc[0]
        
        # Aggregate as multiple
        threats.append({
            "id": f"FLX-ERR-STORM:{str(errors_5xx['timestamp'].min())[-8:]}",
            "rule_id": "FLX-ERR-STORM",
            "type": "Error Storm",
            "category": "Infrastructure",
            "severity": "medium",
            "ip": "Multiple",
            "count": len(errors_5xx),
            "detail": detail,
            "urls": urls,
            "timestamp": str(errors_5xx["timestamp"].min()),
            "last_seen": str(errors_5xx["timestamp"].max()),
            "method": "GET/POST",
            "url": "Multiple",
            "status_code": 500,
            "user_agent": "Multiple",
            "log_line": first["raw"],
            "confidence_score": 75,
            "false_positive_flag": 0,
            "fp_reason": "",
            "mitre_tactic": "Impact",
            "mitre_technique_id": "T1498",
            "recommendation": "Check web server error logs, server capacity, and review recent updates/deployments."
        })
    return threats


# ─── Master Runner ────────────────────────────────────────────────────────────

def run_all_detections(df: pd.DataFrame) -> list[dict]:
    """
    Run all rule-based and signature threat detections on the parsed log dataframe.
    """
    all_threats = []
    
    # 1. Auth attacks
    all_threats += detect_brute_force(df)
    all_threats += detect_credential_stuffing(df)
    all_threats += detect_password_spraying(df)
    
    # 2. Injections
    all_threats += _detect_by_regex(df, "FLX-004", "sql_injection", "url")
    all_threats += _detect_by_regex(df, "FLX-005", "blind_sql_injection", "url")
    all_threats += _detect_by_regex(df, "FLX-006", "command_injection", "url")
    all_threats += _detect_by_regex(df, "FLX-007", "xss_reflected", "url")
    all_threats += _detect_by_regex(df, "FLX-008", "xss_stored", "url")
    all_threats += _detect_by_regex(df, "FLX-009", "xss_dom", "url")
    
    # 3. File Attacks
    all_threats += _detect_by_regex(df, "FLX-010", "lfi", "url")
    all_threats += _detect_by_regex(df, "FLX-011", "rfi", "url")
    all_threats += _detect_by_regex(df, "FLX-012", "directory_traversal", "url")
    all_threats += _detect_by_regex(df, "FLX-013", "webshell_upload", "url")
    all_threats += _detect_by_regex(df, "FLX-014", "webshell_execution", "url")
    
    # 4. Access Control / Session
    all_threats += _detect_by_regex(df, "FLX-016", "open_redirect", "url")
    all_threats += _detect_by_regex(df, "FLX-017", "forced_browsing", "url")
    all_threats += _detect_by_regex(df, "FLX-018", "admin_panel_recon", "url")
    all_threats += _detect_by_regex(df, "FLX-019", "user_enumeration", "url")
    all_threats += _detect_by_regex(df, "FLX-020", "api_abuse", "url")
    
    # 5. Recon & Infrastructure
    all_threats += detect_port_scan_indicators(df)
    all_threats += _detect_by_regex(df, "FLX-023", "bot_crawler", "user_agent")
    all_threats += detect_ddos_indicators(df)
    all_threats += detect_error_storm(df)
    
    # 6. Other Enterprise threats
    all_threats += _detect_by_regex(df, "FLX-025", "sensitive_data_exposure", "raw")
    all_threats += _detect_by_regex(df, "FLX-026", "auth_bypass", "url")
    all_threats += _detect_by_regex(df, "FLX-027", "privilege_escalation", "url")
    all_threats += _detect_by_regex(df, "FLX-028", "js_injection", "url")
    all_threats += _detect_by_regex(df, "FLX-029", "csp_bypass", "url")
    all_threats += _detect_by_regex(df, "FLX-030", "session_weak_ids", "raw")
    
    # Sort by severity then timestamp
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_threats.sort(key=lambda t: (severity_order.get(t["severity"], 9), t["timestamp"]))
    
    print(f"[ThreatEngine] Advanced detection run complete. {len(all_threats)} threats detected.")
    return all_threats


# ─── Backward Compatibility Aliases ──────────────────────────────────────────

def detect_flood(df: pd.DataFrame) -> list[dict]:
    return detect_ddos_indicators(df)

def detect_traversal(df: pd.DataFrame) -> list[dict]:
    return _detect_by_regex(df, "FLX-012", "directory_traversal", "url")

def detect_scanners(df: pd.DataFrame) -> list[dict]:
    return _detect_by_regex(df, "FLX-023", "bot_crawler", "user_agent")

