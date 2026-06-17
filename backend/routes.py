"""
ForensicLogX — Flask Routes / API Endpoints
Includes both batch-upload routes and real-time agent push endpoint.
"""

import os, json
from datetime import datetime
from flask import (Blueprint, render_template, request, jsonify,
                   send_file, current_app, session)
from werkzeug.utils import secure_filename

from backend.parser           import parse_log_file, get_summary
from backend.threat_engine    import run_all_detections
from backend.integrity        import compute_sha256, save_hash, ChainOfCustody
from backend.ip_blocker       import generate_rules, apply_rules
from backend.report_generator import generate_pdf_report

import re

main_bp = Blueprint("main", __name__)

import logging
logger = logging.getLogger("ForensicLogX.routes")
if not logger.handlers and not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

def get_session_analysis(analysis_id=None):
    if not analysis_id:
        # 1. Try to get from request query params
        if request:
            try:
                analysis_id = request.args.get("analysis_id")
            except Exception:
                pass
        
        # 2. Try to get from request JSON body
        if not analysis_id and request:
            try:
                if request.is_json:
                    analysis_id = (request.get_json() or {}).get("analysis_id")
            except Exception:
                pass
                
        # 3. Try to get from request form data
        if not analysis_id and request:
            try:
                analysis_id = request.form.get("analysis_id")
            except Exception:
                pass

        # 4. Fall back to session
        if not analysis_id:
            analysis_id = session.get("analysis_id")

    if not analysis_id:
        return None

    logger.info("Retrieving analysis for ID: %s", analysis_id)

    # Try to load from SQLite database first
    from backend.models import DB_PATH
    import sqlite3
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM forensic_analysis WHERE id = ?", (analysis_id,)).fetchone()
            if row:
                res = dict(row)
                logger.info("Found analysis record in SQLite DB for ID: %s", analysis_id)
                return {
                    "filename": res.get("filename"),
                    "filepath": res.get("filepath"),
                    "file_hash": res.get("file_hash"),
                    "analyst": res.get("analyst"),
                    "organization": res.get("organization"),
                    "summary": json.loads(res.get("summary") or "{}"),
                    "threats": json.loads(res.get("threats") or "[]"),
                    "custody": json.loads(res.get("custody") or "[]"),
                    "analyzed": res.get("timestamp"),
                    "analysis_id": analysis_id
                }
    except Exception as db_err:
        logger.error("Database query failed in get_session_analysis: %s", db_err)

    # Fall back to server-side JSON file
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    analysis_path = os.path.join(upload_folder, f"analysis_{analysis_id}.json")
    if os.path.exists(analysis_path):
        try:
            with open(analysis_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                data["analysis_id"] = analysis_id
                logger.info("Found analysis file on disk for ID: %s", analysis_id)
                return data
        except Exception as file_err:
            logger.error("Failed to read analysis file %s: %s", analysis_path, file_err)
            return None
            
    logger.warning("No analysis found in DB or disk for ID: %s", analysis_id)
    return None

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "ERROR": 7,
    "WARNING": 4,
    "NOTICE": 2
}

def parse_apache_timestamp(ts_str):
    # Remove microseconds if present, e.g. "Mon Jan 01 12:00:00.000000 2025" -> "Mon Jan 01 12:00:00 2025"
    ts_str = re.sub(r'\.\d+', '', ts_str)
    try:
        dt = datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Y")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            dt = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return ts_str

def parse_modsecurity_log(raw_line):
    # Extract timestamp from beginning
    ts_match = re.match(r'^\[([^\]]+)\]', raw_line)
    ts_raw = ts_match.group(1) if ts_match else ""
    timestamp = parse_apache_timestamp(ts_raw) if ts_raw else datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    
    # Extract client IP
    ip_match = re.search(r'\[client\s+([\d\.]+)(?::\d+)?\]', raw_line)
    attacker_ip = ip_match.group(1) if ip_match else "127.0.0.1"
    
    # Extract rule ID
    rule_match = re.search(r'\[id\s+"(\d+)"\]', raw_line)
    rule_id = rule_match.group(1) if rule_match else "000000"
    
    # Extract severity
    sev_match = re.search(r'\[severity\s+"([^"]+)"\]', raw_line)
    severity = sev_match.group(1).upper() if sev_match else "NOTICE"
    
    # Extract msg
    msg_match = re.search(r'\[msg\s+"([^"]+)"\]', raw_line)
    message = msg_match.group(1) if msg_match else ""
    
    # Extract target variable
    target_match = re.search(r"against variable `([^']*?)'", raw_line)
    target = target_match.group(1) if target_match else ""
    
    # Extract matched data
    data_match = re.search(r'\[data\s+"([^"]+)"\]', raw_line)
    matched_data = data_match.group(1) if data_match else ""
    
    # Extract rule file
    file_match = re.search(r'\[file\s+"([^"]+)"\]', raw_line)
    crs_rule_file = file_match.group(1) if file_match else ""
    
    # Extract all tags
    owasp_tags = re.findall(r'\[tag\s+"([^"]+)"\]', raw_line)
    
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "attacker_ip": attacker_ip,
        "target": target,
        "matched_data": matched_data,
        "owasp_tags": owasp_tags,
        "crs_rule_file": crs_rule_file,
        "timestamp": timestamp
    }

def classify_attack(rule_id):
    try:
        rid = int(rule_id)
    except (ValueError, TypeError):
        return "Other"
    
    if 941000 <= rid < 942000:
        return "XSS"
    elif 942000 <= rid < 943000:
        return "SQL Injection"
    elif 930000 <= rid < 931000:
        return "LFI / Path Traversal"
    elif 931000 <= rid < 932000:
        return "RFI"
    elif 932000 <= rid < 933000:
        return "RCE"
    elif 933000 <= rid < 934000:
        return "PHP Injection"
    elif 944000 <= rid < 945000:
        return "Java Attack"
    elif 921000 <= rid < 922000:
        return "HTTP Protocol Attack"
    elif 913000 <= rid < 914000:
        return "Scanner / Recon"
    else:
        return "Other"

def allowed_file(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_EXTENSIONS"]

def get_engine():
    return current_app.realtime_engine

# ─── Pages ───────────────────────────────────────────────────────────────────
@main_bp.route("/")
def index():
    return render_template("index.html")

@main_bp.route("/favicon.ico")
def favicon():
    return send_file(os.path.join(current_app.root_path, "frontend", "static", "favicon.png"), mimetype="image/png")

# ═══════════════════════════════════════════════════════════════════════════════
#  REAL-TIME AGENT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@main_bp.route("/api/agent/connect", methods=["POST"])
def agent_connect():
    """Agent calls this when it starts up."""
    data       = request.get_json() or {}
    agent_name = data.get("agent_name", "ForensicLogX-Agent")
    engine     = get_engine()
    engine.mark_agent_connected(agent_name)
    # Broadcast to all browser clients
    from backend.socket_events import emit_to_all
    emit_to_all(engine, "agent_status", {"connected": True, "name": agent_name})
    emit_to_all(engine, "snapshot", engine.get_snapshot())
    return jsonify({"status": "connected", "agent": agent_name})


@main_bp.route("/api/agent/disconnect", methods=["POST"])
def agent_disconnect():
    """Agent calls this on shutdown."""
    engine = get_engine()
    engine.mark_agent_disconnected()
    from backend.socket_events import emit_to_all
    emit_to_all(engine, "agent_status", {"connected": False})
    return jsonify({"status": "disconnected"})


@main_bp.route("/api/agent/push", methods=["POST"])
def agent_push():
    """
    Main endpoint — agent pushes a batch of raw log lines here.
    Body: { "lines": ["line1", "line2", ...], "agent_name": "..." }
    """
    data  = request.get_json()
    if not data or "lines" not in data:
        return jsonify({"error": "Missing 'lines' field"}), 400

    lines  = data["lines"]
    engine = get_engine()

    from backend.socket_events import emit_to_all

    new_threats_all = []
    for raw in lines:
        result = engine.ingest_line(raw)
        if result["entry"]:
            # Emit each parsed log line to browsers in real time
            emit_to_all(engine, "new_log", result["entry"])
        if result["new_threats"]:
            for t in result["new_threats"]:
                emit_to_all(engine, "new_threat", t)
                new_threats_all.append(t)

    # Send updated dashboard counters every push
    snap = engine.get_snapshot()
    emit_to_all(engine, "stats_update", {
        "total":        snap["total"],
        "unique_ips":   snap["unique_ips"],
        "error_rate":   snap["error_rate"],
        "threat_count": snap["threat_count"],
        "top_ips":      snap["top_ips"],
        "hour_dist":    snap["hour_dist"],
        "status_dist":  snap["status_dist"],
        "sigma_stats":  snap["sigma_stats"],
    })

    return jsonify({
        "accepted":     len(lines),
        "new_threats":  len(new_threats_all),
        "total_so_far": snap["total"],
    })


@main_bp.route("/api/agent/status", methods=["GET"])
def agent_status():
    snap = get_engine().get_snapshot()
    return jsonify({
        "connected":    snap["agent_connected"],
        "name":         snap["agent_name"],
        "last_seen":    snap["agent_last_seen"],
        "total_lines":  snap["total"],
        "threats":      snap["threat_count"],
    })


@main_bp.route("/api/sigma/stats", methods=["GET"])
def sigma_stats():
    engine = get_engine()
    snap = engine.get_snapshot()
    return jsonify(snap.get("sigma_stats", {}))


@main_bp.route("/api/sigma/rules/list", methods=["GET"])
def sigma_rules_list():
    rules = getattr(current_app, "sigma_rules", [])
    out = []
    for r in rules:
        out.append({
            "id": r.get("id"),
            "title": r.get("title"),
            "level": r.get("level", "unknown"),
            "description": r.get("description", ""),
            "category": r.get("logsource", {}).get("category", "unknown"),
            "path": r.get("_rel_path", ""),
            "tags": r.get("tags", []),
            "author": r.get("author", "Unknown"),
            # Include detection in text/yaml format if possible, or just the dict
            "detection": r.get("detection", {})
        })
    return jsonify(out)



@main_bp.route("/api/logs/ingest", methods=["POST"])
def logs_ingest():
    import sqlite3
    from backend.crs_parser import DB_PATH
    from backend.realtime_engine import parse_line
    from backend.socket_events import emit_to_all

    data = request.get_json() or {}
    raw_log = data.get("raw_log", "").strip()
    log_type = data.get("log_type", "vulnlab_access")
    source = data.get("source", "DVWA")

    if not raw_log:
        return jsonify({"error": "Missing 'raw_log' field"}), 400

    engine = get_engine()
    
    # Mark agent as connected
    agent_name = f"log_agent@{source}"
    engine.mark_agent_connected(agent_name)
    emit_to_all(engine, "agent_status", {"connected": True, "name": agent_name})

    timestamp = datetime.utcnow().isoformat() + "Z"

    # Save in raw_logs
    db_insert_raw_log(timestamp, source, "log_agent", log_type, raw_log)

    if log_type == "vulnlab_error" and "ModSecurity" in raw_log:
        parsed = parse_modsecurity_log(raw_log)
        if parsed:
            attack_type = classify_attack(parsed["rule_id"])
            sev_score = SEVERITY_SCORES.get(parsed["severity"], 2)
            
            # Update threat stats in engine
            engine.update_threat_stats(attack_type, parsed["attacker_ip"], parsed["severity"])
            
            # Run Sigma Rules Engine for error logs
            sigma_rules = getattr(current_app, "sigma_rules", [])
            from backend.sigma_engine import match_sigma_rules
            sigma_matches = match_sigma_rules(raw_log, sigma_rules, log_type)
            for rule in sigma_matches:
                hit = {
                    "rule_id": rule.get("id"),
                    "title": rule.get("title"),
                    "level": rule.get("level"),
                    "description": rule.get("description", ""),
                    "attacker_ip": parsed["attacker_ip"],
                    "raw_log": raw_log,
                    "timestamp": parsed["timestamp"],
                    "category": rule.get("logsource", {}).get("category", "webserver")
                }
                engine.update_sigma_stats(hit)
                emit_to_all(engine, "sigma_alert", hit)
                
                db_insert_detected_attack(
                    hit["timestamp"], hit["attacker_ip"], hit["rule_id"],
                    hit["category"], hit["level"], hit["description"],
                    hit["title"], "", "", 403, "", raw_log,
                    1, log_type, f"Sigma Alert: {hit['title']}", get_recommendation(hit["category"])
                )
            
            # Save to database tables
            db_insert_modsec_alert(
                parsed["timestamp"], parsed["attacker_ip"], "", "", 403, 
                int(parsed["rule_id"]), parsed["message"], parsed["severity"], 
                attack_type, 1, "", raw_log
            )
            
            rec = get_recommendation(attack_type)
            db_insert_detected_attack(
                parsed["timestamp"], parsed["attacker_ip"], int(parsed["rule_id"]),
                attack_type, parsed["severity"], parsed["message"], parsed["matched_data"],
                "", "", 403, "", raw_log, 1, log_type, f"Blocked by ModSecurity: {attack_type}", rec
            )
            
            db_update_attacker_ip(parsed["attacker_ip"], parsed["timestamp"], True)
            
            # Emit modsec_threat event
            emit_to_all(engine, 'modsec_threat', {
                "rule_id": parsed["rule_id"],
                "attack_type": attack_type,
                "severity": parsed["severity"],
                "severity_score": sev_score,
                "attacker_ip": parsed["attacker_ip"],
                "target": parsed["target"],
                "matched_data": parsed["matched_data"],
                "owasp_tags": parsed["owasp_tags"],
                "message": parsed["message"],
                "timestamp": parsed["timestamp"]
            })
            
            # Also add to engine threats so it's persistent in the session
            parsed["attack_type"] = attack_type
            t_std = engine.add_modsec_threat(parsed)
            
            # Emit standard new_threat event so standard lists update
            if t_std:
                emit_to_all(engine, "new_threat", t_std)
            
            # Broadcast updated counters
            snap = engine.get_snapshot()
            emit_to_all(engine, "stats_update", {
                "total":        snap["total"],
                "unique_ips":   snap["unique_ips"],
                "error_rate":   snap["error_rate"],
                "threat_count": snap["threat_count"],
                "top_ips":      snap["top_ips"],
                "hour_dist":    snap["hour_dist"],
                "status_dist":  snap["status_dist"],
                "sigma_stats":  snap["sigma_stats"],
            })
            
            return jsonify({"status": "success", "accepted": 1})

    elif log_type == "vulnlab_access":
        parsed = parse_line(raw_log)
        if parsed:
            db_insert_parsed_web_log(
                parsed["timestamp"], parsed["ip"], parsed["method"],
                parsed["url"], parsed["status"], parsed["user_agent"],
                log_type, raw_log
            )
            emit_to_all(engine, "new_log", parsed)
            
            # Run Sigma Rules Engine for access logs
            sigma_rules = getattr(current_app, "sigma_rules", [])
            from backend.sigma_engine import match_sigma_rules
            sigma_matches = match_sigma_rules(raw_log, sigma_rules, log_type)
            for rule in sigma_matches:
                hit = {
                    "rule_id": rule.get("id"),
                    "title": rule.get("title"),
                    "level": rule.get("level"),
                    "description": rule.get("description", ""),
                    "attacker_ip": parsed["ip"],
                    "raw_log": raw_log,
                    "timestamp": parsed["timestamp"],
                    "category": rule.get("logsource", {}).get("category", "webserver")
                }
                engine.update_sigma_stats(hit)
                emit_to_all(engine, "sigma_alert", hit)
                
                db_insert_detected_attack(
                    hit["timestamp"], hit["attacker_ip"], hit["rule_id"],
                    hit["category"], hit["level"], hit["description"],
                    hit["title"], parsed["method"], parsed["url"],
                    parsed["status"], parsed["user_agent"], raw_log,
                    0, log_type, f"Sigma Alert: {hit['title']}", get_recommendation(hit["category"])
                )
            
            # Run engine ingest (updates engine metrics and returns simple threats)
            ingest_result = engine.ingest_line(raw_log)
            if ingest_result["new_threats"]:
                for t in ingest_result["new_threats"]:
                    emit_to_all(engine, "new_threat", t)
            
            # Run the CRSDetector signature matching
            from backend.crs_routes import _get_detector
            detector = _get_detector()
            crs_alerts = detector.analyze_line(raw_log, save=False)
            
            for alert in crs_alerts:
                is_blocked = parsed["status"] in (401, 403, 406)
                status_text = "Blocked by ModSecurity CRS" if is_blocked else "Detected from Web Server Logs"
                rec = get_recommendation(alert["category"])
                
                db_insert_detected_attack(
                    alert["timestamp"], alert["source_ip"], alert["rule_id"],
                    alert["category"], alert["severity"], alert["description"],
                    alert["matched_pattern"], alert["method"], alert["url"],
                    alert["status_code"], alert["user_agent"], raw_log,
                    1 if is_blocked else 0, log_type, status_text, rec
                )
                
                # Update Attacker IPs
                db_update_attacker_ip(alert["source_ip"], alert["timestamp"], is_blocked)
                
                # Emit new threat to UI
                t_event = {
                    "id": f"agent:{alert['rule_id']}:{alert['source_ip']}:{alert['timestamp'][-8:]}",
                    "type": alert["category"],
                    "severity": alert["severity"].lower(),
                    "ip": alert["source_ip"],
                    "detail": f"{status_text}: {alert['description']}",
                    "count": 1,
                    "url": alert["url"],
                    "timestamp": alert["timestamp"]
                }
                engine.add_threat_event(t_event)
                emit_to_all(engine, "new_threat", t_event)

    # Send updated dashboard counters every push
    snap = engine.get_snapshot()
    emit_to_all(engine, "stats_update", {
        "total":        snap["total"],
        "unique_ips":   snap["unique_ips"],
        "error_rate":   snap["error_rate"],
        "threat_count": snap["threat_count"],
        "top_ips":      snap["top_ips"],
        "hour_dist":    snap["hour_dist"],
        "status_dist":  snap["status_dist"],
        "sigma_stats":  snap["sigma_stats"],
    })

    return jsonify({"status": "success", "accepted": 1})


# ─── New Agent & Test Lab Endpoints ──────────────────────────────────────────

def db_insert_raw_log(timestamp, hostname, agent_id, log_source, raw_log):
    import sqlite3
    from backend.crs_parser import DB_PATH
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO raw_logs (timestamp, hostname, agent_id, log_source, raw_log) VALUES (?, ?, ?, ?, ?)",
            (timestamp, hostname, agent_id, log_source, raw_log)
        )
        conn.commit()


def db_insert_parsed_web_log(timestamp, source_ip, method, url, status_code, user_agent, log_source, raw_log):
    import sqlite3
    from backend.crs_parser import DB_PATH
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO parsed_web_logs (timestamp, source_ip, method, url, status_code, user_agent, log_source, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, source_ip, method, url, status_code, user_agent, log_source, raw_log)
        )
        conn.commit()


def db_insert_modsec_alert(timestamp, source_ip, method, url, status_code, rule_id, rule_message, severity, attack_category, blocked, transaction_id, raw_log):
    import sqlite3
    from backend.crs_parser import DB_PATH
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO modsecurity_alerts (timestamp, source_ip, method, url, status_code, rule_id, rule_message, severity, attack_category, blocked, transaction_id, raw_log) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, source_ip, method, url, status_code, rule_id, rule_message, severity, attack_category, blocked, transaction_id, raw_log)
        )
        conn.commit()


def db_insert_detected_attack(timestamp, source_ip, rule_id, category, severity, description, matched_pattern, method, url, status_code, user_agent, log_line, blocked, log_source, attack_type, recommendation):
    import sqlite3
    from backend.crs_parser import DB_PATH
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO detected_attacks (timestamp, source_ip, rule_id, category, severity, description, matched_pattern, method, url, status_code, user_agent, log_line, blocked, log_source, attack_type, recommendation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, source_ip, rule_id, category, severity, description, matched_pattern, method, url, status_code, user_agent, log_line, blocked, log_source, attack_type, recommendation)
        )
        conn.commit()


def db_update_attacker_ip(ip, timestamp, is_blocked):
    import sqlite3
    from backend.crs_parser import DB_PATH
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT attack_count, blocked FROM attacker_ips WHERE ip = ?", (ip,)).fetchone()
        if row:
            count = row[0] + 1
            blocked_val = 1 if (row[1] or is_blocked) else 0
            conn.execute(
                "UPDATE attacker_ips SET attack_count = ?, last_seen = ?, blocked = ? WHERE ip = ?",
                (count, timestamp, blocked_val, ip)
            )
        else:
            conn.execute(
                "INSERT INTO attacker_ips (ip, attack_count, first_seen, last_seen, blocked) VALUES (?, 1, ?, ?, ?)",
                (ip, timestamp, timestamp, 1 if is_blocked else 0)
            )
        conn.commit()


def get_recommendation(attack_type):
    attack_type = (attack_type or "").lower()
    if "sql" in attack_type:
        return "Enforce input validation, use prepared statements (Parameterized Queries), and enable ModSecurity SQLi rules (942xxx)."
    elif "xss" in attack_type or "cross-site" in attack_type:
        return "Sanitize input, encode output fields, enforce a strict Content Security Policy (CSP), and enable ModSecurity XSS rules (941xxx)."
    elif "rce" in attack_type or "command" in attack_type or "execution" in attack_type:
        return "Avoid shell execution functions (system, exec, passthru), restrict system permissions, and block IP immediately using firewalls."
    elif "traversal" in attack_type or "lfi" in attack_type or "inclusion" in attack_type:
        return "Enforce strict path validation (basename), restrict directory access, and configure open_basedir in PHP."
    elif "upload" in attack_type or "webshell" in attack_type:
        return "Validate uploaded file extensions and MIME types, store files outside the document root, and disable execution permissions on upload directories."
    elif "brute" in attack_type:
        return "Implement CAPTCHA, set lockout policies for failed logins, enforce rate limiting, and deploy fail2ban on the authentication system."
    elif "scanner" in attack_type or "recon" in attack_type or "nikto" in attack_type:
        return "Block identified scanner User-Agents, configure rate limiting, and restrict access to administrative panels."
    else:
        return "Investigate the raw log event, review security group rules, and temporarily block the source IP address."


@main_bp.route("/api/agent/logs", methods=["POST"])
def agent_logs():
    import sqlite3
    import re
    from backend.crs_parser import DB_PATH
    from backend.realtime_engine import parse_line
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data received"}), 400
        
    if isinstance(data, dict):
        logs = [data]
    elif isinstance(data, list):
        logs = data
    else:
        return jsonify({"error": "Invalid format"}), 400
        
    engine = get_engine()
    from backend.socket_events import emit_to_all
    
    # Preload detector
    from backend.crs_routes import _get_detector
    detector = _get_detector()
    
    # We will import ModSecParser dynamically to parse audit logs
    from backend.modsec_log_parser import ModSecParser
    from backend.crs_parser import CRSParser
    crs_rules = CRSParser().get_all_rules()
    modsec_parser = ModSecParser(crs_rules=crs_rules)
    
    processed_count = 0
    threats_detected = 0
    
    for entry in logs:
        agent_id = entry.get("agent_id", "Unknown")
        hostname = entry.get("hostname", "Unknown")
        log_source = entry.get("log_source", "Unknown")
        timestamp = entry.get("timestamp")
        raw_log = entry.get("raw_log", "").strip()
        
        if not raw_log:
            continue
            
        if timestamp == "auto" or not timestamp:
            timestamp = datetime.utcnow().isoformat() + "Z"
            
        # 1. Save in raw_logs
        db_insert_raw_log(timestamp, hostname, agent_id, log_source, raw_log)
        processed_count += 1
        
        # 2. Parse and detect based on log_source
        if log_source in ("apache_access", "nginx_access"):
            # Parse the log line
            parsed = parse_line(raw_log)
            if parsed:
                db_insert_parsed_web_log(
                    parsed["timestamp"], parsed["ip"], parsed["method"],
                    parsed["url"], parsed["status"], parsed["user_agent"],
                    log_source, raw_log
                )
                
                # Emit raw log line to UI in real time
                emit_to_all(engine, "new_log", parsed)
                
                # Run engine ingest (updates engine metrics and returns simple threats)
                engine.ingest_line(raw_log)
                
                # Run the CRSDetector signature matching
                crs_alerts = detector.analyze_line(raw_log, save=False)
                
                for alert in crs_alerts:
                    threats_detected += 1
                    # Determine blocked or allowed status
                    is_blocked = False
                    if parsed["status"] in (401, 403, 406):
                        is_blocked = True
                    else:
                        # Check database for recent block
                        with sqlite3.connect(DB_PATH) as conn:
                            row = conn.execute(
                                "SELECT 1 FROM modsecurity_alerts WHERE source_ip = ? AND url = ? AND blocked = 1 ORDER BY id DESC LIMIT 1",
                                (parsed["ip"], parsed["url"])
                            ).fetchone()
                            if row:
                                is_blocked = True
                                
                    status_text = "Blocked by ModSecurity CRS" if is_blocked else "Detected from Web Server Logs"
                    rec = get_recommendation(alert["category"])
                    
                    db_insert_detected_attack(
                        alert["timestamp"], alert["source_ip"], alert["rule_id"],
                        alert["category"], alert["severity"], alert["description"],
                        alert["matched_pattern"], alert["method"], alert["url"],
                        alert["status_code"], alert["user_agent"], raw_log,
                        1 if is_blocked else 0, log_source, status_text, rec
                    )
                    
                    # Update Attacker IPs
                    db_update_attacker_ip(alert["source_ip"], alert["timestamp"], is_blocked)
                    
                    # Emit new threat to UI
                    t_event = {
                        "id": f"agent:{alert['rule_id']}:{alert['source_ip']}:{alert['timestamp'][-8:]}",
                        "type": alert["category"],
                        "severity": alert["severity"].lower(),
                        "ip": alert["source_ip"],
                        "detail": f"{status_text}: {alert['description']}",
                        "count": 1,
                        "url": alert["url"],
                        "timestamp": alert["timestamp"]
                    }
                    engine.add_threat_event(t_event)
                    emit_to_all(engine, "new_threat", t_event)
                    
        elif log_source == "modsec_audit":
            # Parse the transaction block
            try:
                txns = modsec_parser.parse_text(raw_log)
                for txn in txns:
                    # Save to modsecurity_alerts
                    for alert in txn.get("alerts", []):
                        db_insert_modsec_alert(
                            txn["timestamp"], txn["source_ip"], txn["method"],
                            txn["url"], txn["status_code"], alert["rule_id"],
                            alert["msg"], alert["severity"], alert["category"],
                            1 if txn["blocked"] else 0, txn["transaction_id"], raw_log
                        )
                        
                        # Save to detected_attacks as Blocked/Detected
                        status_text = "Blocked by ModSecurity CRS" if txn["blocked"] else "Detected from Web Server Logs"
                        rec = get_recommendation(alert["category"])
                        
                        db_insert_detected_attack(
                            txn["timestamp"], txn["source_ip"], alert["rule_id"],
                            alert["category"], alert["severity"], alert["msg"],
                            alert.get("data", ""), txn["method"], txn["url"],
                            txn["status_code"], "", raw_log,
                            1 if txn["blocked"] else 0, log_source, status_text, rec
                        )
                        
                        db_update_attacker_ip(txn["source_ip"], txn["timestamp"], txn["blocked"])
                        threats_detected += 1
                        
                        # Emit to UI
                        t_event = {
                            "id": f"modsec:{alert['rule_id']}:{txn['source_ip']}:{txn['timestamp'][-8:]}",
                            "type": alert["category"],
                            "severity": alert["severity"].lower(),
                            "ip": txn["source_ip"],
                            "detail": f"{status_text}: {alert['msg']}",
                            "count": 1,
                            "url": txn["url"],
                            "timestamp": txn["timestamp"]
                        }
                        engine.add_threat_event(t_event)
                        emit_to_all(engine, "new_threat", t_event)
            except Exception as e:
                print(f"[Error] Failed to parse modsec audit log: {e}")
                
        elif log_source == "auth_log":
            if "Failed password" in raw_log or "Authentication failure" in raw_log or "Invalid user" in raw_log:
                ip_match = re.search(r'from\s+([\d.]+)', raw_log)
                ip = ip_match.group(1) if ip_match else "Unknown"
                
                status_text = "Detected from Web Server Logs"
                rec = get_recommendation("brute")
                
                db_insert_detected_attack(
                    timestamp, ip, 999100, "Brute Force", "HIGH",
                    "SSH/Auth Authentication Failure", raw_log, "", "", 0, "",
                    raw_log, 0, log_source, status_text, rec
                )
                
                db_update_attacker_ip(ip, timestamp, False)
                threats_detected += 1
                
                t_event = {
                    "id": f"auth:brute:{ip}:{timestamp[-8:]}",
                    "type": "Brute Force",
                    "severity": "high",
                    "ip": ip,
                    "detail": f"Authentication Failure in auth.log: {raw_log[:100]}",
                    "count": 1,
                    "url": "SSH / Local Auth",
                    "timestamp": timestamp
                }
                engine.add_threat_event(t_event)
                emit_to_all(engine, "new_threat", t_event)

    # Send updated dashboard counters every push
    snap = engine.get_snapshot()
    emit_to_all(engine, "stats_update", {
        "total":        snap["total"],
        "unique_ips":   snap["unique_ips"],
        "error_rate":   snap["error_rate"],
        "threat_count": snap["threat_count"],
        "top_ips":      snap["top_ips"],
        "hour_dist":    snap["hour_dist"],
        "status_dist":  snap["status_dist"],
    })

    return jsonify({
        "status": "success",
        "processed": processed_count,
        "threats": threats_detected
    })


@main_bp.route("/api/agent/heartbeat", methods=["POST"])
def agent_heartbeat():
    data = request.get_json() or {}
    engine = get_engine()
    
    engine.agent_connected = True
    engine.agent_name = data.get("hostname", "Unknown")
    engine.agent_last_seen = datetime.now().isoformat()
    engine.agent_info = {
        "status": data.get("agent_status", "online"),
        "hostname": data.get("hostname", "Unknown"),
        "os": data.get("os", "Linux"),
        "cpu_usage": data.get("cpu_usage", "0.0%"),
        "memory_usage": data.get("memory_usage", "0.0%"),
        "disk_usage": data.get("disk_usage", "0.0%"),
        "last_seen": engine.agent_last_seen
    }
    
    from backend.socket_events import emit_to_all
    emit_to_all(engine, "agent_heartbeat", engine.agent_info)
    emit_to_all(engine, "agent_status", {"connected": True, "name": engine.agent_name})
    return jsonify({"status": "heartbeat_received"})


@main_bp.route("/api/testlab/status", methods=["GET"])
def testlab_status():
    import sqlite3
    from backend.crs_parser import DB_PATH
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            
            total_attacks = conn.execute("SELECT COUNT(*) FROM detected_attacks").fetchone()[0]
            modsec_alerts = conn.execute("SELECT COUNT(*) FROM modsecurity_alerts").fetchone()[0]
            
            last_log_row = conn.execute("SELECT timestamp FROM raw_logs ORDER BY id DESC LIMIT 1").fetchone()
            last_log_time = last_log_row[0] if last_log_row else "Never"
            
            sqli_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='SQL Injection' OR category='SQLi')").fetchone()[0]
            sqli_blind_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='SQL Injection (Blind)')").fetchone()[0]
            xss_reflected_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='XSS (Reflected)' OR category='XSS')").fetchone()[0]
            xss_stored_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='XSS (Stored)')").fetchone()[0]
            xss_dom_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='XSS (DOM)')").fetchone()[0]
            csrf_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='CSRF')").fetchone()[0]
            cmd_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='Command Injection' OR category='RCE')").fetchone()[0]
            upload_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='File Upload' OR category='WebShell')").fetchone()[0]
            traversal_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='File Inclusion' OR category='LFI' OR category='RFI')").fetchone()[0]
            captcha_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='Insecure CAPTCHA')").fetchone()[0]
            weak_id_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='Weak Session IDs' OR category='SessionFixation')").fetchone()[0]
            csp_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='CSP Bypass')").fetchone()[0]
            javascript_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='JavaScript Attacks')").fetchone()[0]
            auth_bypass_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='Authorisation Bypass')").fetchone()[0]
            redirect_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='Open HTTP Redirect')").fetchone()[0]
            crypto_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='Cryptography')").fetchone()[0]
            api_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='API')").fetchone()[0]
            brute_detected = conn.execute("SELECT EXISTS(SELECT 1 FROM detected_attacks WHERE category='Brute Force')").fetchone()[0]
            
            sources_rows = conn.execute("SELECT DISTINCT log_source FROM raw_logs").fetchall()
            connected_logs = [row[0] for row in sources_rows]

            # Fetch latest 10 ModSec alerts
            alerts_rows = conn.execute(
                "SELECT timestamp, source_ip, rule_id, rule_message, severity, attack_category FROM modsecurity_alerts ORDER BY id DESC LIMIT 10"
            ).fetchall()
            latest_alerts = [dict(row) for row in alerts_rows]
            
        engine = get_engine()
        agent_info = getattr(engine, "agent_info", {})
        
        return jsonify({
            "success": True,
            "connected_logs": connected_logs,
            "last_log_time": last_log_time,
            "total_attacks": total_attacks,
            "modsec_alerts": modsec_alerts,
            "agent_info": agent_info,
            "latest_alerts": latest_alerts,
            "checklist": {
                "sqli": bool(sqli_detected),
                "sqli_blind": bool(sqli_blind_detected),
                "xss_reflected": bool(xss_reflected_detected),
                "xss_stored": bool(xss_stored_detected),
                "xss_dom": bool(xss_dom_detected),
                "csrf": bool(csrf_detected),
                "cmd": bool(cmd_detected),
                "upload": bool(upload_detected),
                "traversal": bool(traversal_detected),
                "captcha": bool(captcha_detected),
                "weak_id": bool(weak_id_detected),
                "csp": bool(csp_detected),
                "javascript": bool(javascript_detected),
                "auth_bypass": bool(auth_bypass_detected),
                "redirect": bool(redirect_detected),
                "crypto": bool(crypto_detected),
                "api": bool(api_detected),
                "brute": bool(brute_detected)
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  SNAPSHOT / LIVE DATA
# ═══════════════════════════════════════════════════════════════════════════════

@main_bp.route("/api/realtime/snapshot", methods=["GET"])
def realtime_snapshot():
    return jsonify(get_engine().get_snapshot())


@main_bp.route("/api/realtime/block", methods=["POST"])
def realtime_block():
    data   = request.get_json() or {}
    ip     = data.get("ip", "")
    actor  = data.get("actor", "Analyst")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    engine = get_engine()
    engine.block_ip(ip, actor)
    from backend.socket_events import emit_to_all
    emit_to_all(engine, "ip_blocked", {"ip": ip})
    emit_to_all(engine, "snapshot", engine.get_snapshot())
    return jsonify({"blocked": ip})


@main_bp.route("/api/realtime/reset", methods=["POST"])
def realtime_reset():
    engine = get_engine()
    engine.reset()
    
    # Clear SQLite database tables
    import sqlite3
    from backend.crs_parser import DB_PATH
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM detected_attacks;")
            conn.execute("DELETE FROM modsecurity_alerts;")
            conn.execute("DELETE FROM raw_logs;")
            conn.execute("DELETE FROM parsed_web_logs;")
            conn.execute("DELETE FROM attacker_ips;")
            conn.commit()
    except Exception as e:
        print(f"[Error] Failed to clear DB tables: {e}")
        
    from backend.socket_events import emit_to_all
    emit_to_all(engine, "snapshot", engine.get_snapshot())
    return jsonify({"status": "reset"})


# ═══════════════════════════════════════════════════════════════════════════════
#  BATCH UPLOAD (kept for backward compat)
# ═══════════════════════════════════════════════════════════════════════════════

@main_bp.route("/api/upload", methods=["POST"])
def upload_log():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file     = request.files["file"]
    analyst  = request.form.get("analyst", "Analyst")
    if not file.filename or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file"}), 400

    filename      = secure_filename(file.filename)
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    hash_folder   = current_app.config["HASH_FOLDER"]
    filepath      = os.path.join(upload_folder, filename)
    file.save(filepath)

    try:
        file_hash = compute_sha256(filepath)
        save_hash(filepath, file_hash, hash_folder)
        coc = ChainOfCustody(analyst, filename, file_hash)
        df  = parse_log_file(filepath)
        coc.add_entry("Log Parsing Complete", f"{len(df)} entries extracted")
        summary = get_summary(df)
        threats = run_all_detections(df)
        coc.add_entry("Threat Detection Complete", f"{len(threats)} threats found")

        # ── Run CRS detector on each log line in memory to generate offline threats ──
        from backend.crs_routes import _get_detector
        detector = _get_detector()

        crs_threats = []
        for _, row in df.iterrows():
            raw_line = row.get("raw", "")
            if not raw_line:
                continue
            crs_alerts = detector.analyze_line(raw_line, save=False)
            for alert in crs_alerts:
                is_blocked = int(row["status"]) in (401, 403, 406)
                status_text = "Blocked by ModSecurity CRS" if is_blocked else "Detected from Uploaded Logs"
                crs_threats.append({
                    "id": f"upload:{alert['rule_id']}:{alert['source_ip']}:{alert['timestamp'][-8:]}",
                    "type": alert["category"],
                    "severity": alert["severity"].lower() if alert["severity"] else "medium",
                    "ip": alert["source_ip"],
                    "count": 1,
                    "detail": f"{status_text}: {alert['description']}",
                    "url": alert["url"],
                    "timestamp": alert["timestamp"]
                })

        all_threats = threats + crs_threats
        coc.add_entry("Forensic Report Compilation", f"{len(all_threats)} total threats identified")

        # ── Store in DB, session, disk, and return ──
        import uuid
        analysis_id = str(uuid.uuid4())
        analysis_path = os.path.join(upload_folder, f"analysis_{analysis_id}.json")
        analysis_data = {
            "filename": filename, "filepath": filepath,
            "file_hash": file_hash, "analyst": analyst,
            "summary": summary, "threats": all_threats,
            "custody": coc.entries, "analyzed": datetime.now().isoformat(),
        }
        
        # Write JSON metadata file to disk
        try:
            with open(analysis_path, "w", encoding="utf-8") as fh:
                json.dump(analysis_data, fh)
            logger.info("Forensic analysis JSON saved to disk: %s", analysis_path)
        except Exception as file_err:
            logger.error("Failed to write analysis JSON file: %s", file_err)

        # Store in SQLite database for persistent database-driven architecture
        from backend.models import DB_PATH
        import sqlite3
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    """
                    INSERT INTO forensic_analysis (id, timestamp, filename, file_hash, analyst, organization, summary, threats, custody, filepath)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        analysis_id,
                        datetime.now().isoformat() + "Z",
                        filename,
                        file_hash,
                        analyst,
                        "BS Digital Forensics & Cyber Security",
                        json.dumps(summary),
                        json.dumps(all_threats),
                        json.dumps(coc.entries),
                        filepath
                    )
                )
                conn.commit()
            logger.info("Forensic analysis successfully stored in database with ID: %s", analysis_id)
        except Exception as db_err:
            logger.error("Failed to insert forensic analysis into DB: %s", db_err)

        session["analysis_id"] = analysis_id
        logger.info("Saved analysis_id to Flask session. Alerts found: %d", len(all_threats))
        
        logs_s = df.head(500).copy()
        logs_s["timestamp"] = logs_s["timestamp"].astype(str)
        logs_s["date"]      = logs_s["date"].astype(str)
        return jsonify({
            "success": True, "filename": filename, "file_hash": file_hash,
            "summary": summary, "threats": all_threats,
            "custody": coc.entries, "logs_sample": logs_s.to_dict(orient="records"),
            "total_logs": len(df),
            "analysis_id": analysis_id
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@main_bp.route("/api/demo", methods=["GET"])
def load_demo():
    demo_threats = [
        {"type":"Brute Force","severity":"critical","ip":"185.220.101.34","count":84,
         "detail":"84 auth failures from 185.220.101.34","timestamp":"2024-03-15 10:00:12",
         "last_seen":"2024-03-15 10:14:55","urls":{"/wp-login.php":70,"/admin":14}},
        {"type":"HTTP Flood / DDoS","severity":"high","ip":"91.108.4.180","count":65,
         "detail":"65 req/min — possible DDoS","timestamp":"2024-03-15 11:30:02",
         "last_seen":"2024-03-15 11:33:40","urls":{"/":65}},
        {"type":"Directory Traversal","severity":"high","ip":"45.33.32.156","count":15,
         "detail":"Path traversal: /../etc/passwd","timestamp":"2024-03-15 11:00:05",
         "last_seen":"2024-03-15 11:01:15","urls":{"/../etc/passwd":10,"/.git/config":5}},
        {"type":"Vulnerability Scanner","severity":"medium","ip":"91.108.4.180","count":30,
         "detail":"Scanner: Nikto — 30 requests","timestamp":"2024-03-15 10:30:00",
         "last_seen":"2024-03-15 10:31:00","urls":{"/phpmyadmin":10,"/wp-admin":20}},
        {"type":"Error Storm","severity":"medium","ip":"Multiple","count":42,
         "detail":"42 server errors (5xx) in last 60s","timestamp":"2024-03-15 11:31:00",
         "last_seen":"2024-03-15 11:33:00","urls":{"/api/data":42}},
    ]
    demo_summary = {
        "total_requests":875,"unique_ips":10,"unique_urls":25,
        "start_time":"2024-03-15 08:00:00","end_time":"2024-03-15 15:00:00",
        "error_count":180,"error_rate_pct":20.6,"bytes_total":18432000,
        "status_dist":{"200":600,"301":40,"302":15,"400":20,"401":80,"403":25,"404":55,"500":40},
        "method_dist":{"GET":720,"POST":130,"PUT":15,"DELETE":10},
        "top_ips":{"192.168.1.105":200,"185.220.101.34":84,"91.108.4.180":95,
                   "10.0.0.22":150,"45.33.32.156":15,"203.0.113.42":80,
                   "198.51.100.7":120,"172.16.0.5":90,"192.0.2.88":30,"8.8.4.4":11},
        "hourly_traffic":{8:120,9:130,10:180,11:250,12:70,13:60,14:65},
    }
    demo_custody = [
        {"timestamp":"2024-03-15T10:00:00","action":"Evidence Collected","detail":"demo_apache_access.log","actor":"Gohar Ali"},
        {"timestamp":"2024-03-15T10:00:01","action":"Hash Computed","detail":"SHA-256: a3f8c2...","actor":"System"},
        {"timestamp":"2024-03-15T10:00:02","action":"Log Parsing Complete","detail":"875 entries","actor":"System"},
        {"timestamp":"2024-03-15T10:00:03","action":"Threat Detection","detail":"5 threats","actor":"System"},
    ]
    # Store demo analysis in server-side JSON and session for report generation
    import uuid
    analysis_id = str(uuid.uuid4())
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    analysis_path = os.path.join(upload_folder, f"analysis_{analysis_id}.json")
    analysis_data = {
        "filename": "demo_apache_access.log",
        "filepath": os.path.join(upload_folder, "demo_apache_access.log"),
        "file_hash": "a3f8c2d91e4b7f0612a85c3d9e2f1b4a7c0d3e6f8a1b4c7d0e3f6a9b2c5d8e1f",
        "analyst": "Gohar Ali",
        "summary": demo_summary,
        "threats": demo_threats,
        "custody": demo_custody,
        "analyzed": datetime.now().isoformat(),
    }
    with open(analysis_path, "w", encoding="utf-8") as fh:
        json.dump(analysis_data, fh)
    session["analysis_id"] = analysis_id

    return jsonify({
        "success":True,"filename":"demo_apache_access.log",
        "file_hash":"a3f8c2d91e4b7f0612a85c3d9e2f1b4a7c0d3e6f8a1b4c7d0e3f6a9b2c5d8e1f",
        "summary":demo_summary,"threats":demo_threats,
        "timeline":sorted(demo_threats,key=lambda t:t["timestamp"]),
        "custody":demo_custody,
    })


@main_bp.route("/api/logs", methods=["GET"])
def get_logs():
    analysis = get_session_analysis()
    if not analysis:
        return jsonify({"error":"No analysis in session"}), 404
    page      = int(request.args.get("page", 0))
    page_size = int(request.args.get("page_size", 50))
    sf = request.args.get("status","all")
    mf = request.args.get("method","all")
    search = request.args.get("search","").lower()
    try:
        df = parse_log_file(analysis["filepath"])
        if sf != "all": df = df[df["status"].astype(str).str.startswith(sf[0])]
        if mf != "all": df = df[df["method"] == mf]
        if search:
            mask = (df["ip"].str.contains(search,na=False) |
                    df["url"].str.lower().str.contains(search,na=False) |
                    df["method"].str.lower().str.contains(search,na=False))
            df = df[mask]
        total   = len(df)
        slice_df = df.iloc[page*page_size:(page+1)*page_size].copy()
        slice_df["timestamp"] = slice_df["timestamp"].astype(str)
        slice_df["date"]      = slice_df["date"].astype(str)
        return jsonify({"logs":slice_df.to_dict(orient="records"),"total":total,
                        "page":page,"page_size":page_size,
                        "pages":(total+page_size-1)//page_size})
    except Exception as e:
        return jsonify({"error":str(e)}), 500


@main_bp.route("/api/verify", methods=["POST"])
def verify():
    data     = request.get_json()
    analysis = get_session_analysis()
    if not analysis:
        return jsonify({"error":"No analysis in session"}), 404
    provided = data.get("hash","").strip()
    stored   = analysis.get("file_hash","")
    return jsonify({"match":provided==stored,"stored_hash":stored,
                    "provided_hash":provided,
                    "status":"match" if provided==stored else "mismatch",
                    "message":"VERIFIED" if provided==stored else "MISMATCH — possible tampering!"})


@main_bp.route("/api/block/rules", methods=["POST"])
def block_rules():
    data = request.get_json()
    ips  = data.get("ips",[])
    if not ips: return jsonify({"error":"No IPs"}), 400
    return jsonify(generate_rules(ips))


@main_bp.route("/api/export/custody", methods=["GET"])
def export_custody():
    analysis = get_session_analysis()
    if not analysis: return jsonify({"error":"No analysis"}), 404
    return jsonify({"case_id":f"FLX-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    "analyst":analysis.get("analyst"),"filename":analysis.get("filename"),
                    "created":datetime.now().isoformat(),"entries":analysis.get("custody",[])})


@main_bp.route("/api/report/generate", methods=["POST"])
def generate_report():
    data = request.get_json() or {}
    analysis_id = data.get("analysis_id")
    
    logger.info("Report generation request received. Analysis ID: %s, Data: %s", analysis_id, data)
    
    # Session / DB retrieval using get_session_analysis
    analysis = get_session_analysis(analysis_id)
    
    if not analysis:
        # Fall back to live engine session data if no specific forensic analysis is requested
        logger.info("No batch analysis found for ID %s. Falling back to live engine telemetry data.", analysis_id)
        engine = get_engine()
        
        # Compute dynamic evidence hash of the threat stream to satisfy forensic standards
        import hashlib
        threats_list = list(engine.threats)
        threats_serialized = json.dumps(threats_list, default=str, sort_keys=True)
        live_hash = hashlib.sha256(threats_serialized.encode('utf-8')).hexdigest()
        
        analysis = {
            "summary": {
                "total_requests": engine.total,
                "unique_ips": len(engine.unique_ips),
                "error_rate_pct": round(engine.error_count / max(engine.total, 1) * 100, 1)
            },
            "threats": threats_list,
            "custody": list(engine.custody),
            "file_hash": live_hash,
            "filename": "Live Log Telemetry"
        }
        
    # Validation before report generation
    if not analysis:
        logger.error("Report generation failed: No analysis session exists.")
        return jsonify({"error": "No analysis session exists. Awaiting log data."}), 400
        
    summary = analysis.get("summary", {})
    total_requests = summary.get("total_requests", 0)
    threats = analysis.get("threats", [])
    custody = analysis.get("custody", [])
    filename = analysis.get("filename", "unknown.log")
    file_hash = analysis.get("file_hash", "N/A")

    logger.info("Validating report inputs. Total requests: %d, Threats: %d", total_requests, len(threats))

    if total_requests == 0 and not threats:
        logger.warning("Aborting report generation: No log events or security alerts available.")
        return jsonify({"error": "No report data available. Analysis summary is empty and no threat alerts were found."}), 400

    analyst = data.get("analyst") or analysis.get("analyst") or "Analyst"
    org = data.get("organization") or analysis.get("organization") or "BS Digital Forensics & Cyber Security"
    
    report_folder = current_app.config["REPORT_FOLDER"]
    report_path = os.path.join(report_folder, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    
    logger.info("Starting PDF compilation to %s...", report_path)
    
    try:
        out = generate_pdf_report(
            output_path=report_path, analyst=analyst, organization=org,
            summary=summary, threats=threats,
            custody_entries=custody, file_hash=file_hash,
            filename=filename
        )
        
        if not os.path.exists(out):
            logger.error("PDF generation failed: File was not created.")
            return jsonify({"error": "PDF generation failed. Output file missing."}), 500
            
        pdf_size = os.path.getsize(out)
        if pdf_size == 0:
            logger.error("PDF generation failed: Created PDF is 0 KB.")
            return jsonify({"error": "PDF generation failed. Generated PDF is 0 KB."}), 500
            
        # Compute and save PDF report SHA-256 hash
        from backend.integrity import compute_sha256, save_hash
        pdf_hash = compute_sha256(out)
        hash_folder = current_app.config["HASH_FOLDER"]
        save_hash(out, pdf_hash, hash_folder)
        
        logger.info("PDF Report generated successfully. Size: %d bytes. SHA-256: %s", pdf_size, pdf_hash)
        return send_file(os.path.abspath(out), as_attachment=True, download_name="forensic_report.pdf",
                         mimetype="application/pdf")
    except Exception as e:
        logger.error("Exception occurred during report generation: %s", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500


@main_bp.route("/api/export/csv", methods=["GET"])
def export_csv():
    analysis = get_session_analysis()
    if not analysis: return jsonify({"error":"No analysis"}),404
    try:
        df = parse_log_file(analysis["filepath"])
        df["timestamp"] = df["timestamp"].astype(str)
        df["date"]      = df["date"].astype(str)
        report_folder = current_app.config["REPORT_FOLDER"]
        csv_path = os.path.join(report_folder,"logs_export.csv")
        df.to_csv(csv_path,index=False)
        return send_file(os.path.abspath(csv_path),as_attachment=True,download_name="logs_export.csv",mimetype="text/csv")
    except Exception as e:
        return jsonify({"error":str(e)}),500


@main_bp.route("/api/threats/stats", methods=["GET"])
def threats_stats():
    return jsonify(get_engine().threat_stats)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTERPRISE RULE-BASED DETECTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

from backend.detection_rules import DETECTION_RULES
from backend.ioc_library import SUSPICIOUS_USER_AGENTS, MALICIOUS_PATH_FRAGMENTS, ADMIN_ENDPOINTS
from backend.fp_handler import FalsePositiveHandler

fp_handler = FalsePositiveHandler()

@main_bp.route("/api/detections/rules", methods=["GET"])
def get_detections_rules():
    return jsonify(DETECTION_RULES)

@main_bp.route("/api/detections/rules/<rule_id>", methods=["GET"])
def get_detections_rule_detail(rule_id):
    rule = DETECTION_RULES.get(rule_id)
    if not rule:
        return jsonify({"error": f"Rule {rule_id} not found"}), 404
    return jsonify(rule)

@main_bp.route("/api/detections/attacks", methods=["GET"])
def get_detections_attacks():
    import sqlite3
    from backend.crs_parser import DB_PATH
    
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 20))
    category = request.args.get("category", "")
    severity = request.args.get("severity", "")
    fp_flag = request.args.get("false_positive_flag", "")
    search = request.args.get("search", "")
    
    offset = (page - 1) * page_size
    
    query = "SELECT * FROM detected_attacks WHERE 1=1"
    count_query = "SELECT COUNT(*) FROM detected_attacks WHERE 1=1"
    params = []
    
    if category:
        query += " AND category = ?"
        count_query += " AND category = ?"
        params.append(category)
    if severity:
        query += " AND LOWER(severity) = ?"
        count_query += " AND LOWER(severity) = ?"
        params.append(severity.lower())
    if fp_flag != "":
        query += " AND false_positive_flag = ?"
        count_query += " AND false_positive_flag = ?"
        params.append(int(fp_flag))
    if search:
        query += " AND (source_ip LIKE ? OR url LIKE ? OR description LIKE ?)"
        count_query += " AND (source_ip LIKE ? OR url LIKE ? OR description LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
        
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    query_params = params + [page_size, offset]
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            total_records = conn.execute(count_query, params).fetchone()[0]
            rows = conn.execute(query, query_params).fetchall()
            attacks = [dict(row) for row in rows]
            
            return jsonify({
                "attacks": attacks,
                "total": total_records,
                "page": page,
                "page_size": page_size,
                "pages": (total_records + page_size - 1) // page_size if total_records > 0 else 0
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route("/api/detections/attacks/summary", methods=["GET"])
def get_detections_attacks_summary():
    import sqlite3
    from backend.crs_parser import DB_PATH
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cat_rows = conn.execute(
                "SELECT category, COUNT(*) as count FROM detected_attacks GROUP BY category"
            ).fetchall()
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as count FROM detected_attacks GROUP BY severity"
            ).fetchall()
            fp_rows = conn.execute(
                "SELECT false_positive_flag, COUNT(*) as count FROM detected_attacks GROUP BY false_positive_flag"
            ).fetchall()
            
            return jsonify({
                "by_category": {r["category"]: r["count"] for r in cat_rows},
                "by_severity": {r["severity"].lower(): r["count"] for r in sev_rows},
                "by_fp": {("FP" if r["false_positive_flag"] == 1 else "TP"): r["count"] for r in fp_rows}
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route("/api/detections/mitre/matrix", methods=["GET"])
def get_detections_mitre_matrix():
    import sqlite3
    from backend.crs_parser import DB_PATH
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT mitre_tactic, mitre_technique_id, COUNT(*) as count 
                FROM detected_attacks 
                WHERE mitre_tactic IS NOT NULL AND mitre_tactic != '' 
                GROUP BY mitre_tactic, mitre_technique_id
            """).fetchall()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route("/api/detections/timeline", methods=["GET"])
def get_detections_timeline():
    import sqlite3
    from backend.crs_parser import DB_PATH
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT substr(timestamp, 1, 13) as hour_bucket, LOWER(severity) as severity, COUNT(*) as count 
                FROM detected_attacks 
                GROUP BY hour_bucket, severity 
                ORDER BY hour_bucket DESC 
                LIMIT 100
            """).fetchall()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route("/api/detections/top-ips", methods=["GET"])
def get_detections_top_ips():
    import sqlite3
    from backend.crs_parser import DB_PATH
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM attacker_ips ORDER BY attack_count DESC LIMIT 10"
            ).fetchall()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route("/api/detections/ioc-library", methods=["GET"])
def get_detections_ioc_library():
    return jsonify({
        "suspicious_user_agents": SUSPICIOUS_USER_AGENTS[:100],
        "malicious_path_fragments": MALICIOUS_PATH_FRAGMENTS,
        "admin_endpoints": ADMIN_ENDPOINTS
    })

@main_bp.route("/api/detections/false-positive/<int:attack_id>", methods=["POST"])
def post_detections_false_positive(attack_id):
    success = fp_handler.mark_fp(attack_id)
    if success:
        return jsonify({"success": True, "message": f"Attack {attack_id} marked as false positive."})
    else:
        return jsonify({"success": False, "error": f"Failed to mark attack {attack_id} as false positive."}), 400

@main_bp.route("/api/detections/response/<rule_id>", methods=["GET"])
def get_detections_response(rule_id):
    rule = DETECTION_RULES.get(rule_id)
    if not rule:
        return jsonify({"error": f"Rule {rule_id} not found"}), 404
    return jsonify(rule.get("recommendation", {}))

@main_bp.route("/api/detections/test-cases", methods=["GET"])
def get_detections_test_cases():
    import json
    import os
    from flask import current_app
    log_file = os.path.join(current_app.root_path, "dataset", "dvwa_test_logs.jsonl")
    cases = []
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    if i >= 50:
                        break
                    try:
                        cases.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify(cases)
